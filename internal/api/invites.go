package api

import (
	"bytes"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/squaddle-org/relay/internal/membership"
	"github.com/squaddle-org/relay/internal/store"
)

// envelopeRateLimiter is a fixed-window per-IP limiter for the unauthenticated envelope GET
// (relay-api.yaml: "rate-limited per IP") - stdlib only; this one endpoint doesn't justify a new
// dependency.
type envelopeRateLimiter struct {
	mu     sync.Mutex
	window time.Duration
	limit  int
	hits   map[string][]time.Time
}

func newEnvelopeRateLimiter() *envelopeRateLimiter {
	return &envelopeRateLimiter{window: time.Minute, limit: 30, hits: map[string][]time.Time{}}
}

func (l *envelopeRateLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	kept := l.hits[ip][:0]
	for _, t := range l.hits[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		l.hits[ip] = kept
		return false
	}
	l.hits[ip] = append(kept, now)
	return true
}

func clientIP(r *http.Request) string {
	if h := r.Header.Get("X-Forwarded-For"); h != "" {
		return h
	}
	return r.RemoteAddr
}

// getInviteEnvelope is `GET /v1/invites/{room}/{invite}/envelope` - unauthenticated, rate
// limited. Checks the invite's revoked/expired/exhausted state against the room's replayed
// membership state (the invite's lifecycle lives there, not in a separate copy) before serving
// the opaque envelope bytes.
func getInviteEnvelope(st *store.Store, limiter *envelopeRateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.allow(clientIP(r), time.Now()) {
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		room, ok1 := b64PathParam(r, "room")
		inviteID, ok2 := b64PathParam(r, "invite")
		if !ok1 || !ok2 {
			writeError(w, http.StatusBadRequest, "invalid", "bad path parameter")
			return
		}
		state, err := st.GetMembershipState(room)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "unknown room")
			return
		}
		var invite *membership.Invite
		for _, inv := range state.Invites() {
			if bytes.Equal(inv.ID, inviteID) {
				i := inv
				invite = &i
				break
			}
		}
		if invite == nil || invite.Revoked {
			writeError(w, http.StatusNotFound, "not_found", "unknown or revoked invite")
			return
		}
		now := uint64(time.Now().Unix())
		expired := invite.ExpiresAt != nil && now >= *invite.ExpiresAt
		exhausted := invite.MaxUses != nil && invite.Uses >= *invite.MaxUses
		if expired || exhausted {
			_ = st.DeleteInviteEnvelope(room, inviteID)
			writeError(w, http.StatusGone, "expired", "invite expired or exhausted")
			return
		}
		envelope, err := st.GetInviteEnvelope(room, inviteID)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "no envelope stored")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(envelope)
	}
}

// putInviteEnvelope is `PUT /v1/invites/{room}/{invite}/envelope` - owner/admin only
// (relay-api.yaml). The relay never creates or decrypts the envelope itself (PROTOCOL.md §3.5) -
// it just stores whatever opaque bytes an authorized admin uploads.
func putInviteEnvelope(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		room, ok1 := b64PathParam(r, "room")
		inviteID, ok2 := b64PathParam(r, "invite")
		if !ok1 || !ok2 {
			writeError(w, http.StatusBadRequest, "invalid", "bad path parameter")
			return
		}
		if !callerIsOwnerOrAdmin(st, room, r) {
			writeError(w, http.StatusForbidden, "forbidden", "owner/admin only")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "cannot read body")
			return
		}
		if err := st.PutInviteEnvelope(room, inviteID, body); err != nil {
			writeError(w, http.StatusInternalServerError, "invalid", "store error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// callerIsOwnerOrAdmin resolves the request-auth-verified device (see auth.go) to its user via
// that device's own registered cert, then checks the user's current role in room.
func callerIsOwnerOrAdmin(st *store.Store, room []byte, r *http.Request) bool {
	device := DeviceKeyFromContext(r.Context())
	if device == nil {
		return false
	}
	cert, err := st.GetDeviceCert(device)
	if err != nil {
		return false
	}
	state, err := st.GetMembershipState(room)
	if err != nil {
		return false
	}
	role, ok := state.RoleOf(cert.User)
	return ok && (role == membership.RoleOwner || role == membership.RoleAdmin)
}
