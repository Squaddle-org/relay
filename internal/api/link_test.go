package api

import (
	"bytes"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/squaddle-org/relay/internal/limits"
	"github.com/squaddle-org/relay/internal/store"
)

func newTestRouter(t *testing.T) http.Handler {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), st, limits.NewPolicy("none", ""), "", nil)
}

func linkPath(code []byte) string {
	return "/v1/link/" + base64.RawURLEncoding.EncodeToString(code)
}

func TestLinkMailboxRoundTripsAndSingleReadDeletes(t *testing.T) {
	h := newTestRouter(t)
	code := []byte("0123456789abcdef")
	blob := []byte("sealed bytes, opaque to the relay")

	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, httptest.NewRequest(http.MethodPost, linkPath(code), bytes.NewReader(blob)))
	if postRec.Code != http.StatusNoContent {
		t.Fatalf("POST got %d, body %q", postRec.Code, postRec.Body.String())
	}

	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, linkPath(code), nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("first GET got %d", getRec.Code)
	}
	if !bytes.Equal(getRec.Body.Bytes(), blob) {
		t.Fatalf("got body %q, want %q", getRec.Body.Bytes(), blob)
	}

	// Single read, deletes (relay-api.yaml) - a second GET for the same code must 404.
	secondGetRec := httptest.NewRecorder()
	h.ServeHTTP(secondGetRec, httptest.NewRequest(http.MethodGet, linkPath(code), nil))
	if secondGetRec.Code != http.StatusNotFound {
		t.Fatalf("second GET got %d, want 404", secondGetRec.Code)
	}
}

func TestLinkMailboxGetMissingCodeReturns404(t *testing.T) {
	h := newTestRouter(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, linkPath([]byte("ffffffffffffffff")), nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
}

// Both link-mailbox routes share a rate limiter instance (router.go's linkLimiter) separate from
// the invite-envelope one - same type (envelopeRateLimiter), 30/minute per IP. httptest.NewRequest
// gives every request in this test the same default RemoteAddr, so they all count against the
// same bucket.
func TestLinkMailboxGetIsRateLimited(t *testing.T) {
	h := newTestRouter(t)
	var lastCode int
	for i := 0; i < 31; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, linkPath([]byte("aaaaaaaaaaaaaaaa")), nil))
		lastCode = rec.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("31st request got %d, want 429", lastCode)
	}
}

func TestLinkMailboxPostIsRateLimited(t *testing.T) {
	h := newTestRouter(t)
	var lastCode int
	for i := 0; i < 31; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, linkPath([]byte("bbbbbbbbbbbbbbbb")), bytes.NewReader([]byte("x"))))
		lastCode = rec.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("31st request got %d, want 429", lastCode)
	}
}
