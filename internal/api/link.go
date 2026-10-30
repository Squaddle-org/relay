package api

import (
	"io"
	"net/http"
	"time"

	"github.com/squaddle-org/relay/internal/store"
)

// linkMailboxTTL is PROTOCOL.md §2.3: "Mailbox entries expire after 5 minutes."
const linkMailboxTTL = 5 * time.Minute

// postLinkMailbox is `POST /v1/link/{code}` - unauthenticated (device linking has no identity
// yet to authenticate with), rate limited per IP - same reasoning and same limiter type as the
// other unauthenticated, security-relevant endpoint in this repo, getInviteEnvelope. The 16-byte
// code itself isn't brute-forceable (128 bits); this is storage-abuse/DoS hygiene, not a
// cryptographic fix.
func postLinkMailbox(st *store.Store, limiter *envelopeRateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.allow(clientIP(r), time.Now()) {
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		code, ok := b64PathParam(r, "code")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid", "bad code path parameter")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "cannot read body")
			return
		}
		expiresAt := uint64(time.Now().Add(linkMailboxTTL).Unix())
		if err := st.PutLinkMailbox(code, body, expiresAt); err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "store error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// getLinkMailbox is `GET /v1/link/{code}` - "single read, deletes" (relay-api.yaml), rate
// limited per IP (see postLinkMailbox's own doc comment).
func getLinkMailbox(st *store.Store, limiter *envelopeRateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.allow(clientIP(r), time.Now()) {
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		code, ok := b64PathParam(r, "code")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid", "bad code path parameter")
			return
		}
		blob, err := st.TakeLinkMailbox(code, uint64(time.Now().Unix()))
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "empty")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(blob)
	}
}
