package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/squaddle-org/relay/internal/membership"
	"github.com/squaddle-org/relay/internal/proto"
	"github.com/squaddle-org/relay/internal/store"
)

// postRoom is `POST /v1/rooms`: creates a room from a genesis LogEntry.
func postRoom(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "cannot read body")
			return
		}
		entry, err := proto.DecodeLogEntry(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "not a canonical LogEntry")
			return
		}
		rts := uint64(time.Now().Unix())
		if _, err := st.CreateRoom(*entry, rts); err != nil {
			writeLogApplyError(w, st, entry.Room, err)
			return
		}
		writeAppended(w, entry.Index, rts)
	}
}

// getLog is `GET /v1/rooms/{room}/log?from=<index>`.
func getLog(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		room, ok := b64PathParam(r, "room")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid", "bad room path parameter")
			return
		}
		from := parseUintQuery(r, "from", 0)
		entries, err := st.GetLogEntriesFrom(room, from)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "store error")
			return
		}
		type wireEntry struct {
			Cbor []byte `cbor:"0,keyasint"`
			Rts  uint64 `cbor:"1,keyasint"`
		}
		wire := make([]wireEntry, len(entries))
		for i, e := range entries {
			wire[i] = wireEntry{Cbor: e.Cbor, Rts: e.Rts}
		}
		out, err := proto.EncodeCanonical(wire)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "encoding error")
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(out)
	}
}

// postLog is `POST /v1/rooms/{room}/log`: appends one LogEntry, validated by
// membership.State.Apply (chain + full §3.3 authorization) exactly as core's own state machine
// does - no separate relay-only business logic. "Non-members may only append `join`"
// (relay-api.yaml) falls out of that same validation: every other entry type requires an
// existing role.
func postLog(st *store.Store, notifier *pushNotifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		room, ok := b64PathParam(r, "room")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid", "bad room path parameter")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "cannot read body")
			return
		}
		entry, err := proto.DecodeLogEntry(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "not a canonical LogEntry")
			return
		}
		rts := uint64(time.Now().Unix())
		if _, err := st.AppendLogEntry(room, *entry, rts); err != nil {
			writeLogApplyError(w, st, room, err)
			return
		}
		runInviteLifecycleSideEffects(st, room, *entry)
		notifier.notify(st, room, int64(entry.Index))
		writeAppended(w, entry.Index, rts)
	}
}

// runInviteLifecycleSideEffects implements PROTOCOL.md §3.5's "Relay deletes the envelope on
// revoke, expiry, or when uses are exhausted." Expiry is checked lazily at GET-envelope time
// (invites.go); revoke and exhaustion are handled right after the entry that causes them, since
// both are only observable right after a successful log append.
func runInviteLifecycleSideEffects(st *store.Store, room []byte, entry proto.LogEntry) {
	switch entry.Type {
	case proto.EntryInviteRevoke:
		if inviteID, ok := entry.Body[0].([]byte); ok {
			_ = st.DeleteInviteEnvelope(room, inviteID)
		}
	case proto.EntryJoin:
		inviteID, ok := entry.Body[0].([]byte)
		if !ok {
			return
		}
		state, err := st.GetMembershipState(room)
		if err != nil {
			return
		}
		for _, inv := range state.Invites() {
			if bytes.Equal(inv.ID, inviteID) && inv.MaxUses != nil && inv.Uses >= *inv.MaxUses {
				_ = st.DeleteInviteEnvelope(room, inviteID)
			}
		}
	}
}

func writeAppended(w http.ResponseWriter, index, rts uint64) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"index": index, "rts": rts})
}

// writeLogApplyError maps store.CreateRoom/AppendLogEntry's error (store sentinels or a
// membership.RejectReason) onto relay-api.yaml's Error schema.
func writeLogApplyError(w http.ResponseWriter, st *store.Store, room []byte, err error) {
	switch err {
	case store.ErrRoomExists:
		writeError(w, http.StatusConflict, "invalid", "room exists")
		return
	case store.ErrRoomNotFound:
		writeError(w, http.StatusNotFound, "not_found", "room not found")
		return
	}
	reason, ok := err.(membership.RejectReason)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	switch reason.Code {
	case "BadSignature":
		writeError(w, http.StatusBadRequest, "bad_signature", reason.Error())
	case "BadChain":
		writeStaleHead(w, st, room)
	case "Unauthorized":
		writeError(w, http.StatusForbidden, "forbidden", reason.Error())
	case "InviteExpired":
		writeError(w, http.StatusGone, "expired", reason.Error())
	case "InviteExhausted":
		writeError(w, http.StatusGone, "exhausted", reason.Error())
	case "InviteRevoked":
		writeError(w, http.StatusNotFound, "not_found", reason.Error())
	default:
		writeError(w, http.StatusBadRequest, "invalid", reason.Error())
	}
}

// writeStaleHead is PROTOCOL.md §3.3: "The relay accepts an append only if prev == currentHead
// (else 409, client refetches and retries)" - includes the current head so the client doesn't
// need a second round trip just to refetch it.
func writeStaleHead(w http.ResponseWriter, st *store.Store, room []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	body := map[string]any{"code": "stale_head", "message": "prev does not match the current head"}
	if state, err := st.GetMembershipState(room); err == nil {
		body["head"] = base64.RawURLEncoding.EncodeToString(state.HeadHash())
	}
	_ = json.NewEncoder(w).Encode(body)
}

func parseUintQuery(r *http.Request, name string, def uint64) uint64 {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}
