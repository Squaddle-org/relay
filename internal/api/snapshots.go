package api

import (
	"bytes"
	"io"
	"net/http"

	"github.com/squaddle-org/relay/internal/proto"
	"github.com/squaddle-org/relay/internal/store"
)

// getLatestSnapshot is `GET /v1/rooms/{room}/snapshots/latest` - members only (§5), opaque (the
// relay never decrypts a Snapshot - PROTOCOL.md §4.4).
func getLatestSnapshot(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		room, ok := b64PathParam(r, "room")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid", "bad room path parameter")
			return
		}
		role, has := callerRole(st, room, r)
		if !isActiveMember(role, has) {
			writeError(w, http.StatusForbidden, "forbidden", "members only")
			return
		}
		snapshot, err := st.GetLatestSnapshot(room)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "no snapshot")
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(snapshot)
	}
}

// postSnapshot is `POST /v1/rooms/{room}/snapshots` - members only. The relay never decrypts Ct,
// but PROTOCOL.md §4.4 now gives Snapshot's fields CBOR field numbers (same table as LogEntry/
// DeviceCert/OpEnvelope), so the outer envelope is decoded and verified structurally exactly like
// postOps does for OpEnvelope: signature must verify and Device must belong to Author. The real
// CoversUpTo is then stored, keying retention pruning (internal/retention) instead of upload time.
func postSnapshot(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		room, ok := b64PathParam(r, "room")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid", "bad room path parameter")
			return
		}
		role, has := callerRole(st, room, r)
		if !isActiveMember(role, has) {
			writeError(w, http.StatusForbidden, "forbidden", "members only")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "cannot read body")
			return
		}
		snapshot, err := proto.DecodeSnapshot(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "not a canonical Snapshot")
			return
		}
		if !snapshot.Verify() {
			writeError(w, http.StatusBadRequest, "bad_signature", "snapshot signature does not verify")
			return
		}
		cert, err := st.GetDeviceCert(snapshot.Device)
		if err != nil || !bytes.Equal(cert.User, snapshot.Author) {
			writeError(w, http.StatusForbidden, "forbidden", "device does not belong to author, or is revoked")
			return
		}
		if err := st.PutSnapshot(room, int64(snapshot.CoversUpTo), body); err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "store error")
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}
