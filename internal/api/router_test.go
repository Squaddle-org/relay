package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/squaddle-org/relay/internal/store"
)

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	NewInternalRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestStubsReturn501(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	h := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), st)
	rec := httptest.NewRecorder()
	// POST /billing/google/rtdn is unauthenticated (security: [] in relay-api.yaml) and still a
	// stub (M5b, out of M2 scope) - safe to hit directly without a signed request.
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/billing/google/rtdn", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("got %d", rec.Code)
	}
}
