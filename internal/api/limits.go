package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/squaddle-org/relay/internal/limits"
	"github.com/squaddle-org/relay/internal/membership"
	"github.com/squaddle-org/relay/internal/proto"
	"github.com/squaddle-org/relay/internal/store"
)

// getLimits is `GET /v1/rooms/{room}/limits` - members only, per PROTOCOL.md §8.1.
func getLimits(st *store.Store, policy *limits.Policy) http.HandlerFunc {
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
		rl, err := limits.Resolve(st, room, policy, time.Now().Unix())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "store error")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tier":             rl.Tier,
			"maxMembers":       rl.MaxMembers,
			"maxPending":       rl.MaxPending,
			"opRetentionDays":  rl.OpRetentionDays,
			"attachmentBytes":  rl.AttachmentBytes,
			"maxActiveInvites": rl.MaxActiveInvites,
			"boostedUntil":     rl.BoostedUntil,
		})
	}
}

// checkLogEntryLimits is §8.2's enforcement, applied before membership.State.Apply ever sees the
// entry (limits are relay policy, never part of the signed log - ADR-0010, so the membership
// state machine itself has no concept of them). Only join/approve (maxMembers) and inviteCreate
// (maxActiveInvites) are gated; every other entry type is unaffected. Returns nil if the entry
// should proceed to the normal Apply() path.
func checkLogEntryLimits(st *store.Store, policy *limits.Policy, room []byte, entry proto.LogEntry) error {
	if entry.Type != proto.EntryJoin && entry.Type != proto.EntryApprove && entry.Type != proto.EntryInviteCreate {
		return nil
	}
	rl, err := limits.Resolve(st, room, policy, time.Now().Unix())
	if err != nil {
		return nil // let the real Apply() surface whatever's actually wrong (e.g. room doesn't exist)
	}
	state, err := st.GetMembershipState(room)
	if err != nil {
		return nil
	}

	switch entry.Type {
	case proto.EntryJoin, proto.EntryApprove:
		if rl.MaxMembers == nil {
			return nil
		}
		nonPending := 0
		for _, m := range state.Members() {
			if m.Role != membership.RolePending {
				nonPending++
			}
		}
		if nonPending >= *rl.MaxMembers {
			return errRoomFull
		}
	case proto.EntryInviteCreate:
		if rl.MaxActiveInvites == nil {
			return nil
		}
		active := 0
		for _, inv := range state.Invites() {
			if !inv.Revoked {
				active++
			}
		}
		if active >= *rl.MaxActiveInvites {
			return errQuotaExceeded
		}
	}
	return nil
}

var (
	errRoomFull      = errors.New("room is full")
	errQuotaExceeded = errors.New("quota exceeded")
)

func writeLimitError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, errRoomFull):
		writeError(w, http.StatusConflict, "room_full", err.Error())
		return true
	case errors.Is(err, errQuotaExceeded):
		writeError(w, http.StatusConflict, "quota_exceeded", err.Error())
		return true
	default:
		return false
	}
}

// postEntitlements is `POST /v1/entitlements` - caller must be a room member (relay-api.yaml).
// Only the `voucher` provider is implemented; `google_play` is explicitly M5b (out of M2 scope,
// see CLAUDE.md's pre-approved dependency list - no Play Developer API client is in scope here).
func postEntitlements(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Room     string `json:"room"`
			Provider string `json:"provider"`
			Token    string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "malformed body")
			return
		}
		room, err := base64.RawURLEncoding.DecodeString(body.Room)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "bad room")
			return
		}
		role, has := callerRole(st, room, r)
		if !isActiveMember(role, has) {
			writeError(w, http.StatusForbidden, "forbidden", "members only")
			return
		}

		switch body.Provider {
		case "voucher":
			postVoucherEntitlement(w, st, room, body.Token)
		case "google_play":
			writeError(w, http.StatusBadRequest, "invalid_entitlement", "google_play is not supported by this relay build (M5b)")
		default:
			writeError(w, http.StatusBadRequest, "invalid_entitlement", "unknown provider")
		}
	}
}

func postVoucherEntitlement(w http.ResponseWriter, st *store.Store, room []byte, code string) {
	codeHash := proto.Blake2b256([]byte(code))
	tier, durationDays, err := st.RedeemVoucher(codeHash, time.Now().Unix())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_entitlement", "voucher not found or already redeemed")
		return
	}

	var until *int64
	if durationDays != nil {
		u := time.Now().Unix() + int64(*durationDays)*86400
		until = &u
	}
	if err := st.PutEntitlement(room, "voucher", base64.RawURLEncoding.EncodeToString(codeHash), tier, until); err != nil {
		if errors.Is(err, store.ErrEntitlementAlreadyBound) {
			writeError(w, http.StatusConflict, "invalid", "voucher already bound to another room")
			return
		}
		writeError(w, http.StatusInternalServerError, "invalid", "store error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"room": base64.RawURLEncoding.EncodeToString(room), "tier": tier, "until": until})
}
