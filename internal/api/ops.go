package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/squaddle-org/relay/internal/membership"
	"github.com/squaddle-org/relay/internal/proto"
	"github.com/squaddle-org/relay/internal/store"
)

// callerRole resolves the request-auth-verified device to its user (via that device's own
// registered cert) and that user's current role in room, mirroring invites.go's
// callerIsOwnerOrAdmin but returning the role itself rather than a boolean, since ops/snapshots
// need to distinguish "no role at all" from "pending" from "a real member".
func callerRole(st *store.Store, room []byte, r *http.Request) (membership.Role, bool) {
	device := DeviceKeyFromContext(r.Context())
	if device == nil {
		return 0, false
	}
	cert, err := st.GetDeviceCert(device)
	if err != nil {
		return 0, false
	}
	state, err := st.GetMembershipState(room)
	if err != nil {
		return 0, false
	}
	return state.RoleOf(cert.User)
}

// isActiveMember is PROTOCOL.md §5: "Read access to ops/snapshots: device's user is
// member/admin/owner (not pending, not removed)."
func isActiveMember(role membership.Role, ok bool) bool {
	return ok && role != membership.RolePending
}

// getOps is `GET /v1/rooms/{room}/ops?after=<cursor>&limit=<n>` - members only (§5).
func getOps(st *store.Store) http.HandlerFunc {
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

		after := int64(parseUintQuery(r, "after", 0))
		limit := int(parseUintQuery(r, "limit", 500))
		if limit <= 0 || limit > 2000 {
			limit = 2000
		}
		ops, err := st.GetOpsAfter(room, after, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "store error")
			return
		}

		type wireOp struct {
			Cursor   int64  `cbor:"0,keyasint"`
			Envelope []byte `cbor:"1,keyasint"`
		}
		wire := make([]wireOp, len(ops))
		next := after
		for i, o := range ops {
			wire[i] = wireOp{Cursor: o.Cursor, Envelope: o.Envelope}
			next = o.Cursor
		}
		out := struct {
			Ops  []wireOp `cbor:"0,keyasint"`
			Next int64    `cbor:"1,keyasint"`
		}{wire, next}
		encoded, err := proto.EncodeCanonical(out)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "encoding error")
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(encoded)
	}
}

// postOps is `POST /v1/rooms/{room}/ops` - "Append a batch of OpEnvelopes (members only, current
// epoch)" (relay-api.yaml). The whole batch is validated before anything is persisted: every
// envelope's signature must verify, its device must belong to its author and not be revoked, and
// its epoch must match the room's current epoch - a single stale/invalid op rejects the entire
// batch (matches "409: stale_epoch" being a batch-level response, not per-op).
func postOps(st *store.Store, notifier *pushNotifier, hub *wsHub) http.HandlerFunc {
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
		var envelopes []proto.OpEnvelope
		if err := proto.DecodeCanonicalInto(body, &envelopes); err != nil || len(envelopes) == 0 {
			writeError(w, http.StatusBadRequest, "invalid", "not a canonical, non-empty OpEnvelope batch")
			return
		}

		state, err := st.GetMembershipState(room)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "room not found")
			return
		}
		if state.RotationPending() {
			writeError(w, http.StatusConflict, "rotation_required", "epoch rotation owed after a recent remove (ADR-0012)")
			return
		}

		for _, op := range envelopes {
			if !op.Verify() {
				writeError(w, http.StatusBadRequest, "bad_signature", "op signature does not verify")
				return
			}
			opCert, err := st.GetDeviceCert(op.Device)
			if err != nil || !bytes.Equal(opCert.User, op.Author) {
				writeError(w, http.StatusForbidden, "forbidden", "device does not belong to author, or is revoked")
				return
			}
			if op.Epoch != state.Epoch() {
				writeError(w, http.StatusConflict, "stale_epoch", "op epoch does not match the room's current epoch")
				return
			}
		}

		cursors := make([]int64, 0, len(envelopes))
		for _, op := range envelopes {
			opID, err := op.OpID()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "invalid", "encoding error")
				return
			}
			full, err := op.FullCbor()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "invalid", "encoding error")
				return
			}
			cursor, err := st.AppendOp(room, opID, op.Device, op.Seq, op.Epoch, full)
			if err != nil {
				writeError(w, http.StatusConflict, "invalid", "duplicate (room, device, seq)")
				return
			}
			cursors = append(cursors, cursor)
		}

		lastCursor := cursors[len(cursors)-1]
		notifier.notify(st, room, lastCursor)
		hub.broadcast(room, lastCursor, "ops")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"cursors": cursors})
	}
}
