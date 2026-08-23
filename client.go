// Package authclient provides an HTTP client for fetching account data
// from bbo-auth-api instead of direct DB reads on t_account.
//
// Design:
//   - Primary: call auth-api GET /api/v1/account/:id for account info
//   - Cache: 10-minute TTL (account data changes rarely)
//   - Redis cache: if a Redis client is set via SetRedisClient, cache is
//     shared across all instances of the service (multi-replica safe)
//   - In-memory cache: fallback if Redis is not configured
//   - Fallback: if auth-api is unreachable, return nil (caller falls back
//     to direct DB read if AUTH_SERVICE_URL not configured)
//
// This is part of P3.1: auth-api becomes the sole owner of t_account.
// Other services fetch account data via this HTTP client instead of
// querying t_account directly.
package authclient

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/natifdevelopment/go-circuitbreaker"
	goredis "github.com/redis/go-redis/v9"
)

// redisKeyPrefix is the Redis key prefix for cached account info.
const redisKeyPrefix = "bbo:auth:account:"

// redisClient is the optional shared Redis client for distributed caching.
// If nil, the client falls back to in-memory cache.
var redisClient *goredis.Client

// metricsServiceName is the service name used for Prometheus metrics labels.
// Set via SetMetricsService before NewClient.
var metricsServiceName string

// MetricsCallbacks allows external systems to observe cache and circuit
// breaker events without this package importing them directly.
type MetricsCallbacks struct {
	OnCacheHit           func()
	OnCacheMiss          func()
	OnStaleServed        func()
	OnCircuitStateChange func(oldState, newState int)
}

// metricsCallbacks holds optional callbacks for observability.
var metricsCallbacks MetricsCallbacks

// SetMetricsCallbacks registers callbacks for cache and circuit breaker events.
// Must be called before NewClient. If not set, events are not recorded.
func SetMetricsCallbacks(cb MetricsCallbacks) {
	metricsCallbacks = cb
}

// TraceInjector is a callback that injects W3C traceparent headers into
// outbound HTTP requests. This allows the caller service (which has OTel)
// to propagate trace context to auth-api without this package importing OTel.
type TraceInjector func(req *http.Request)

// traceInjector holds the optional trace header injector.
var traceInjector TraceInjector

// SetTraceInjector registers a callback that injects trace headers into
// outbound HTTP requests. Must be called before NewClient.
// If not set, trace headers are not injected (tracing context not propagated).
func SetTraceInjector(injector TraceInjector) {
	traceInjector = injector
}

// AccountInfo is the response from auth-api GET /account/:id.
// It contains decrypted account fields (auth-api is the sole decryptor).
type AccountInfo struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	Email            string     `json:"email"`
	PhoneNumber      string     `json:"phoneNumber,omitempty"`
	NIP              string     `json:"nip,omitempty"`
	OrganizationID   *uuid.UUID `json:"organizationId,omitempty"`
	OrganizationName string     `json:"organizationName,omitempty"`
	OrganizationCode string     `json:"organizationCode,omitempty"`
	AccessLevelID    *uuid.UUID `json:"accessLevelId,omitempty"`
	AccessLevelName  string     `json:"accessLevelName,omitempty"`
	AccessLevelCode  string     `json:"accessLevelCode,omitempty"`
}

// cacheEntry holds a cached account response with its fetch time.
type cacheEntry struct {
	account   AccountInfo
	fetchedAt time.Time
}

// Client is the HTTP client for auth-api's account endpoint.
// It is safe for concurrent use.
type Client struct {
	baseURL      string
	httpClient   *http.Client
	sharedSecret string

	cacheMu sync.RWMutex
	cache   map[uuid.UUID]cacheEntry

	cacheTTL time.Duration
	cb       *circuitbreaker.CircuitBreaker
}

// SetRedisClient sets a shared Redis client for distributed caching.
// If set, account info is cached in Redis (shared across all service instances)
// instead of in-memory (per-instance). This is recommended for multi-replica deployments.
// Must be called before NewClient.
func SetRedisClient(client *goredis.Client) {
	redisClient = client
}

// NewClient creates a new auth-api client.
// baseURL is the auth-api base URL (e.g. "http://bbo-auth-api:8080").
// sharedSecret is the GATEWAY_SHARED_SECRET for HMAC signing.
func NewClient(baseURL string, sharedSecret string) *Client {
	transport := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     30 * time.Second,
	}

	// Configure mTLS if enabled (same pattern as pkg/approval)
	if os.Getenv("MTLS_ENABLED") == "true" {
		// TLS config is built from env vars MTLS_CA_CERT_PATH, MTLS_CERT_PATH, MTLS_KEY_PATH
		// Reuse the same pattern — for now, just skip if not configured
	}

	cb := circuitbreaker.New(circuitbreaker.DefaultConfig())
	if metricsCallbacks.OnCircuitStateChange != nil {
		cb.OnStateChange(func(oldState, newState circuitbreaker.State) {
			metricsCallbacks.OnCircuitStateChange(int(oldState), int(newState))
		})
	}

	return &Client{
		baseURL:      baseURL,
		httpClient:   &http.Client{Timeout: 3 * time.Second, Transport: transport},
		sharedSecret: sharedSecret,
		cache:        make(map[uuid.UUID]cacheEntry),
		cacheTTL:     10 * time.Minute,
		cb:           cb,
	}
}

// GetAccountByID fetches account info from auth-api.
// Returns (account, true) on success, (zero, false) if not found or error.
// Uses cache with 10-minute TTL; stale cache served if API is unreachable.
// Circuit breaker: if auth-api is consistently failing, requests short-circuit
// to stale cache fallback without hitting the API (saves latency).
func (c *Client) GetAccountByID(id uuid.UUID) (AccountInfo, bool) {
	// Try cache first (fresh)
	if entry, ok := c.getCacheIfFresh(id); ok {
		if metricsCallbacks.OnCacheHit != nil {
			metricsCallbacks.OnCacheHit()
		}
		return entry.account, true
	}
	if metricsCallbacks.OnCacheMiss != nil {
		metricsCallbacks.OnCacheMiss()
	}

	// Circuit breaker: skip API call if circuit is open
	if !c.cb.AllowRequest() {
		// Circuit open — try stale cache
		if entry, ok := c.getCacheIfStale(id); ok {
			if metricsCallbacks.OnStaleServed != nil {
				metricsCallbacks.OnStaleServed()
			}
			return entry.account, true
		}
		return AccountInfo{}, false
	}

	// Call auth-api
	account, err := c.callAPI(id)
	if err == nil {
		c.cb.RecordSuccess()
		c.setCache(id, *account)
		return *account, true
	}

	// API failed
	c.cb.RecordFailure()

	// Try stale cache
	if entry, ok := c.getCacheIfStale(id); ok {
		if metricsCallbacks.OnStaleServed != nil {
			metricsCallbacks.OnStaleServed()
		}
		return entry.account, true
	}

	// No cache — return not found
	return AccountInfo{}, false
}

// GetAccountsByIDs fetches multiple accounts in a single HTTP call.
// Returns a map of account ID → AccountInfo for all found accounts.
// Accounts not found are omitted from the map.
// Uses cache for individual IDs; uncached IDs are fetched in batch.
// Max 100 IDs per call (enforced by auth-api).
func (c *Client) GetAccountsByIDs(ids []uuid.UUID) map[uuid.UUID]AccountInfo {
	result := make(map[uuid.UUID]AccountInfo)
	if len(ids) == 0 {
		return result
	}

	var uncached []uuid.UUID
	for _, id := range ids {
		if entry, ok := c.getCacheIfFresh(id); ok {
			result[id] = entry.account
		} else {
			uncached = append(uncached, id)
		}
	}

	if len(uncached) == 0 {
		return result
	}

	// Circuit breaker: skip API call if circuit is open
	if !c.cb.AllowRequest() {
		for _, id := range uncached {
			if entry, ok := c.getCacheIfStale(id); ok {
				result[id] = entry.account
			}
		}
		return result
	}

	// Batch fetch uncached IDs
	batchResult, err := c.callBatchAPI(uncached)
	if err != nil {
		c.cb.RecordFailure()
		// API failed — try stale cache for each uncached ID
		for _, id := range uncached {
			if entry, ok := c.getCacheIfStale(id); ok {
				result[id] = entry.account
			}
		}
		return result
	}

	c.cb.RecordSuccess()

	// Cache and add to result
	for id, account := range batchResult {
		c.setCache(id, account)
		result[id] = account
	}

	return result
}

// callAPI makes the HTTP GET to auth-api.
func (c *Client) callAPI(id uuid.UUID) (*AccountInfo, error) {
	endpoint := fmt.Sprintf("%s/api/v1/account/%s", c.baseURL, id.String())

	req, err := http.NewRequest(http.MethodGet, endpoint, bytes.NewReader(nil))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	// Inject W3C traceparent header for distributed tracing (P6.2)
	if traceInjector != nil {
		traceInjector(req)
	}

	// Sign request with HMAC-SHA256 using GATEWAY_SHARED_SECRET
	if c.sharedSecret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(c.sharedSecret))
		mac.Write([]byte(http.MethodGet + "\n" + req.URL.Path + "\n" + ts))
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Gateway-Signature", sig)
		req.Header.Set("X-Gateway-Timestamp", ts)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call auth-api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("account not found")
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("auth-api returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Status bool        `json:"status"`
		Data   AccountInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result.Data, nil
}

// callBatchAPI makes the HTTP POST to auth-api's batch endpoint.
func (c *Client) callBatchAPI(ids []uuid.UUID) (map[uuid.UUID]AccountInfo, error) {
	endpoint := fmt.Sprintf("%s/api/v1/account/batch", c.baseURL)

	body, err := json.Marshal(map[string]interface{}{"ids": ids})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Inject W3C traceparent header for distributed tracing (P6.2)
	if traceInjector != nil {
		traceInjector(req)
	}

	// Sign request with HMAC-SHA256
	if c.sharedSecret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(c.sharedSecret))
		mac.Write([]byte(http.MethodPost + "\n" + req.URL.Path + "\n" + ts))
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Gateway-Signature", sig)
		req.Header.Set("X-Gateway-Timestamp", ts)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call auth-api batch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("auth-api batch returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Status bool             `json:"status"`
		Data   BatchAPIResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return result.Data.Accounts, nil
}

// BatchAPIResponse is the response structure from auth-api batch endpoint.
type BatchAPIResponse struct {
	Accounts map[uuid.UUID]AccountInfo `json:"accounts"`
}

// --- Cache helpers ---

func (c *Client) getCacheIfFresh(id uuid.UUID) (cacheEntry, bool) {
	// Try Redis first (if configured)
	if redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		key := redisKeyPrefix + id.String()
		data, err := redisClient.Get(ctx, key).Bytes()
		if err == nil {
			var account AccountInfo
			if json.Unmarshal(data, &account) == nil {
				return cacheEntry{account: account, fetchedAt: time.Now()}, true
			}
		}
		// Redis miss or error — fall through to in-memory
	}

	// In-memory cache
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	entry, ok := c.cache[id]
	if !ok {
		return entry, false
	}
	if time.Since(entry.fetchedAt) > c.cacheTTL {
		return entry, false
	}
	return entry, true
}

func (c *Client) getCacheIfStale(id uuid.UUID) (cacheEntry, bool) {
	// Redis doesn't have "stale" — if key exists, it's fresh (TTL not expired)
	// If Redis is configured and key is gone, there's no stale cache to serve.
	// Fall through to in-memory stale cache.

	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	entry, ok := c.cache[id]
	return entry, ok
}

func (c *Client) setCache(id uuid.UUID, account AccountInfo) {
	// Set in Redis (if configured)
	if redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		key := redisKeyPrefix + id.String()
		data, err := json.Marshal(account)
		if err == nil {
			redisClient.Set(ctx, key, data, c.cacheTTL)
		}
	}

	// Also set in-memory (as fallback for when Redis is down)
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cache[id] = cacheEntry{
		account:   account,
		fetchedAt: time.Now(),
	}
}
