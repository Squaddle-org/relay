package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/squaddle-org/relay/internal/limits"
	"github.com/squaddle-org/relay/internal/store"
)

const testAllowedOrigin = "https://app.squaddle.org"

func newTestRouterWithCORS(t *testing.T, allowedOriginsCSV string) http.Handler {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	policy := limits.NewPolicy("none", "")
	return NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), st, policy, allowedOriginsCSV)
}

func TestCORSPreflightOnAuthenticatedRouteNeedsNoAuthorizationHeader(t *testing.T) {
	h := newTestRouterWithCORS(t, testAllowedOrigin)

	req := httptest.NewRequest(http.MethodOptions, "/v1/rooms", nil)
	req.Header.Set("Origin", testAllowedOrigin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight: got %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != testAllowedOrigin {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, testAllowedOrigin)
	}
	if rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatal("Access-Control-Allow-Methods missing")
	}
	if rec.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Fatal("Access-Control-Allow-Headers missing")
	}
}

// Unauthenticated routes (e.g. the invite envelope GET) have no auth() wrapper at all - method-
// specific mux patterns never match OPTIONS, so without CORS sitting in front of the mux this
// would 404 instead of answering the preflight.
func TestCORSPreflightOnUnauthenticatedRouteStillAnswers(t *testing.T) {
	h := newTestRouterWithCORS(t, testAllowedOrigin)

	req := httptest.NewRequest(http.MethodOptions, "/v1/invites/"+b64([]byte("room"))+"/"+b64([]byte("invite"))+"/envelope", nil)
	req.Header.Set("Origin", testAllowedOrigin)
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight on unauthenticated route: got %d, want 204", rec.Code)
	}
}

func TestCORSAllowedOriginEchoedOnRealRequest(t *testing.T) {
	h := newTestRouterWithCORS(t, testAllowedOrigin)

	req := httptest.NewRequest(http.MethodGet, "/v1/link/"+b64([]byte("0123456789abcdef")), nil)
	req.Header.Set("Origin", testAllowedOrigin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != testAllowedOrigin {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, testAllowedOrigin)
	}
}

// CORS is a browser-enforced boundary only - a disallowed-origin request still gets processed
// normally server-side (request-auth per §5 is the real authorization boundary); it just won't
// carry the header a browser needs to let its own JS read the response.
func TestCORSDisallowedOriginStillProcessedButNotEchoed(t *testing.T) {
	h := newTestRouterWithCORS(t, testAllowedOrigin)

	req := httptest.NewRequest(http.MethodGet, "/v1/link/"+b64([]byte("0123456789abcdef")), nil)
	req.Header.Set("Origin", "https://evil.example.org")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want empty for a disallowed origin", got)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disallowed-origin request: got %d, want the same 404 an empty mailbox always gives", rec.Code)
	}
}

func TestCORSEmptyAllowlistSendsNoHeaders(t *testing.T) {
	h := newTestRouterWithCORS(t, "")

	req := httptest.NewRequest(http.MethodGet, "/v1/link/"+b64([]byte("0123456789abcdef")), nil)
	req.Header.Set("Origin", testAllowedOrigin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want empty when no origins are configured", got)
	}
}
