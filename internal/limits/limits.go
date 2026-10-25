// Package limits implements PROTOCOL.md §8: relay-local room limits and boosts. Deliberately
// never touches the signed membership log (ADR-0010) - a room keeps working unchanged if it
// moves to another relay.
package limits

import (
	"encoding/base32"
	"strings"

	"github.com/squaddle-org/relay/internal/membership"
	"github.com/squaddle-org/relay/internal/store"
)

// Tier is PROTOCOL.md §8.1's RoomLimits.tier.
type Tier string

const (
	TierFree      Tier = "free"
	TierBoosted   Tier = "boosted"
	TierUnlimited Tier = "unlimited"
)

// RoomLimits mirrors PROTOCOL.md §8.1's JSON shape exactly (GET /rooms/{room}/limits). nil
// fields are the schema's own `null` = unlimited.
type RoomLimits struct {
	Tier             Tier
	MaxMembers       *int
	MaxPending       *int
	OpRetentionDays  *int
	AttachmentBytes  *int
	MaxActiveInvites *int
	BoostedUntil     *int64
}

func Free() RoomLimits {
	maxMembers, retention, maxPending, maxActiveInvites := 20, 90, 20, 5
	return RoomLimits{
		Tier: TierFree, MaxMembers: &maxMembers, OpRetentionDays: &retention,
		AttachmentBytes: zeroInt(), MaxPending: &maxPending, MaxActiveInvites: &maxActiveInvites,
	}
}

func Boosted(until int64) RoomLimits {
	maxMembers, attachmentBytes, maxPending, maxActiveInvites := 100, 1<<30, 50, 25
	return RoomLimits{
		Tier: TierBoosted, MaxMembers: &maxMembers, AttachmentBytes: &attachmentBytes, BoostedUntil: &until,
		MaxPending: &maxPending, MaxActiveInvites: &maxActiveInvites,
	}
}

func Unlimited() RoomLimits { return RoomLimits{Tier: TierUnlimited} }

func zeroInt() *int { z := 0; return &z }

// Policy is the relay-wide, operator-configured side of §8: the `-limits` mode and the
// `-unlimited-owners` allowlist (§8.1a).
type Policy struct {
	Hosted          bool
	unlimitedOwners map[string]bool // hex(userKey) -> true
}

// NewPolicy parses `-limits=none|hosted` and a comma-separated `-unlimited-owners` list of
// base32 user keys (PROTOCOL.md §2.1's UserId display convention).
func NewPolicy(mode, unlimitedOwnersCSV string) *Policy {
	owners := map[string]bool{}
	for _, entry := range strings.Split(unlimitedOwnersCSV, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		userKey, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(entry))
		if err != nil {
			continue
		}
		owners[hexKey(userKey)] = true
	}
	return &Policy{Hosted: mode == "hosted", unlimitedOwners: owners}
}

func hexKey(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexChars[v>>4]
		out[i*2+1] = hexChars[v&0x0F]
	}
	return string(out)
}

// Resolve is §8's precedence: unlimited > boosted > free, evaluated fresh against the room's
// *current* owner (§8.1a: "Evaluated on every limits check, so it follows transferOwner").
// Self-hosted relays (`-limits=none`, the default) are always unlimited regardless of owner or
// entitlements.
func Resolve(st *store.Store, roomID []byte, policy *Policy, nowUnix int64) (RoomLimits, error) {
	if !policy.Hosted {
		return Unlimited(), nil
	}

	state, err := st.GetMembershipState(roomID)
	if err != nil {
		return RoomLimits{}, err
	}
	for _, m := range state.Members() {
		if m.Role == membership.RoleOwner && policy.unlimitedOwners[hexKey(m.User)] {
			return Unlimited(), nil
		}
	}

	ent, err := st.GetActiveEntitlement(roomID, nowUnix)
	if err != nil {
		return RoomLimits{}, err
	}
	if ent != nil {
		if ent.Until == nil {
			return Unlimited(), nil
		}
		return Boosted(*ent.Until), nil
	}

	return Free(), nil
}
