package authclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGetAccountByID_APISuccess(t *testing.T) {
	accountID := uuid.New()
	orgID := uuid.New()
	alID := uuid.New()

	server := mockAuthAPI(t, AccountInfo{
		ID:               accountID,
		Name:             "John Doe",
		Email:            "john@example.com",
		OrganizationID:   &orgID,
		OrganizationName: "ICONPLN",
		AccessLevelID:    &alID,
		AccessLevelCode:  "superadmin",
	}, http.StatusOK)
	defer server.Close()

	client := NewClient(server.URL, "test-secret")
	account, ok := client.GetAccountByID(accountID)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if account.Name != "John Doe" {
		t.Fatalf("expected name 'John Doe', got %q", account.Name)
	}
	if account.AccessLevelCode != "superadmin" {
		t.Fatalf("expected access level 'superadmin', got %q", account.AccessLevelCode)
	}
}

func TestGetAccountByID_CacheHit(t *testing.T) {
	callCount := 0
	accountID := uuid.New()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": true,
			"data":   AccountInfo{ID: accountID, Name: "Cached User"},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-secret")

	// First call hits API
	account1, ok1 := client.GetAccountByID(accountID)
	if !ok1 || account1.Name != "Cached User" {
		t.Fatal("first call failed")
	}

	// Second call should hit cache
	account2, ok2 := client.GetAccountByID(accountID)
	if !ok2 || account2.Name != "Cached User" {
		t.Fatal("second call (cache) failed")
	}
	if callCount != 1 {
		t.Fatalf("expected 1 API call, got %d", callCount)
	}
}

func TestGetAccountByID_APIError_NoCache(t *testing.T) {
	client := NewClient("http://localhost:9999", "test-secret") // unreachable
	_, ok := client.GetAccountByID(uuid.New())
	if ok {
		t.Fatal("expected ok=false when API unreachable and no cache")
	}
}

func TestGetAccountByID_StaleCacheServedOnAPIFailure(t *testing.T) {
	callCount := 0
	accountID := uuid.New()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": true,
			"data":   AccountInfo{ID: accountID, Name: "Stale User"},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-secret")
	client.cacheTTL = 1 * time.Millisecond

	// First call hits API and caches
	account1, ok1 := client.GetAccountByID(accountID)
	if !ok1 || account1.Name != "Stale User" {
		t.Fatal("first call failed")
	}

	// Wait for cache to become stale
	time.Sleep(10 * time.Millisecond)

	// Point client to unreachable server
	client.baseURL = "http://localhost:9999"

	// Should serve stale cache
	account2, ok2 := client.GetAccountByID(accountID)
	if !ok2 {
		t.Fatal("expected ok=true from stale cache")
	}
	if account2.Name != "Stale User" {
		t.Fatalf("expected 'Stale User', got %q", account2.Name)
	}
}

func TestGetAccountByID_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "not found"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-secret")
	_, ok := client.GetAccountByID(uuid.New())
	if ok {
		t.Fatal("expected ok=false for 404")
	}
}

func TestGetAccountByID_HMACSignature(t *testing.T) {
	var receivedSig, receivedTs string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Gateway-Signature")
		receivedTs = r.Header.Get("X-Gateway-Timestamp")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": true,
			"data":   AccountInfo{ID: uuid.New(), Name: "Test"},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "my-secret")
	client.GetAccountByID(uuid.New())

	if receivedSig == "" {
		t.Fatal("expected X-Gateway-Signature header")
	}
	if receivedTs == "" {
		t.Fatal("expected X-Gateway-Timestamp header")
	}
}

func mockAuthAPI(t *testing.T, account AccountInfo, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": true,
			"data":   account,
		})
	}))
}

func TestGetAccountsByIDs_APISuccess(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()
	id3 := uuid.New() // not in API response

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/account/batch" {
			accounts := map[uuid.UUID]AccountInfo{
				id1: {ID: id1, Name: "User One"},
				id2: {ID: id2, Name: "User Two"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": true,
				"data":   map[string]interface{}{"accounts": accounts},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-secret")
	result := client.GetAccountsByIDs([]uuid.UUID{id1, id2, id3})

	if len(result) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(result))
	}
	if result[id1].Name != "User One" {
		t.Fatalf("expected 'User One', got %q", result[id1].Name)
	}
	if result[id2].Name != "User Two" {
		t.Fatalf("expected 'User Two', got %q", result[id2].Name)
	}
	if _, ok := result[id3]; ok {
		t.Fatal("expected id3 to be absent")
	}
}

func TestGetAccountsByIDs_CacheHit(t *testing.T) {
	id := uuid.New()
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		accounts := map[uuid.UUID]AccountInfo{
			id: {ID: id, Name: "Cached User"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": true,
			"data":   map[string]interface{}{"accounts": accounts},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-secret")

	// First call hits API
	result1 := client.GetAccountsByIDs([]uuid.UUID{id})
	if result1[id].Name != "Cached User" {
		t.Fatal("first call failed")
	}

	// Second call should hit cache (no new API call)
	result2 := client.GetAccountsByIDs([]uuid.UUID{id})
	if result2[id].Name != "Cached User" {
		t.Fatal("second call (cache) failed")
	}
	if callCount != 1 {
		t.Fatalf("expected 1 API call, got %d", callCount)
	}
}

func TestGetAccountsByIDs_EmptyInput(t *testing.T) {
	client := NewClient("http://localhost:9999", "test-secret")
	result := client.GetAccountsByIDs([]uuid.UUID{})
	if len(result) != 0 {
		t.Fatalf("expected empty map, got %d", len(result))
	}
}

func TestGetAccountsByIDs_APIError_StaleCache(t *testing.T) {
	id := uuid.New()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accounts := map[uuid.UUID]AccountInfo{
			id: {ID: id, Name: "Stale User"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": true,
			"data":   map[string]interface{}{"accounts": accounts},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-secret")
	client.cacheTTL = 1 * time.Millisecond

	// First call hits API and caches
	client.GetAccountsByIDs([]uuid.UUID{id})

	// Wait for cache to become stale
	time.Sleep(10 * time.Millisecond)

	// Point to unreachable server
	client.baseURL = "http://localhost:9999"

	// Should serve stale cache
	result := client.GetAccountsByIDs([]uuid.UUID{id})
	if result[id].Name != "Stale User" {
		t.Fatalf("expected 'Stale User' from stale cache, got %q", result[id].Name)
	}
}
