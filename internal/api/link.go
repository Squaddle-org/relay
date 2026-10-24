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
// yet to authenticate with).
func postLinkMailbox(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

// getLinkMailbox is `GET /v1/link/{code}` - "single read, deletes" (relay-api.yaml).
func getLinkMailbox(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
