package api

import (
	"io"
	"net/http"
	"time"

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

// postSnapshot is `POST /v1/rooms/{room}/snapshots` - members only, opaque.
//
// KNOWN LIMITATION: PROTOCOL.md §4.4 names Snapshot's fields (room, epoch, coversUpTo, nonce, ct,
// author, device, sig) but - unlike every other structure in the spec - never gives them CBOR
// field numbers. Without that table this handler cannot parse the client's real `coversUpTo`
// (needed to key retention pruning, PROTOCOL.md §4.4/§8) out of the opaque blob without guessing
// a wire format. It stores the blob keyed by upload time instead (good enough for "latest
// snapshot", not yet good enough for precise "ops covered by a snapshot" pruning in B9) and signs
// nothing - the relay already can't decrypt or verify this structure's content either way. A
// spec PR adding Snapshot's field-number table (mirroring LogEntry/DeviceCert/OpEnvelope) should
// land before B9's retention pruning is implemented for real.
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
		if err := st.PutSnapshot(room, time.Now().UnixNano(), body); err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "store error")
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}
