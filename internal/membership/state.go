package membership

import (
	"bytes"
	"encoding/hex"

	"github.com/squaddle-org/relay/internal/proto"
)

// State is the pure §3.3 state machine, ported field-for-field from core's
// MembershipStateImpl.kt. Apply never mutates - it always returns a brand new *State (or an
// error), so a caller can keep a reference to an old state safely.
//
// Two authorization rules go slightly beyond the literal §3.3 table text, both mirrored exactly
// from core (see MembershipStateImpl.kt's own doc comment): epochRotate must bump epoch by
// exactly 1, and inviteCreate rejects a duplicate inviteId. RotationPending is ADR-0012.
type State struct {
	roomID          []byte
	headHash        []byte
	nextIndex       uint64
	epoch           uint64
	roles           map[string]Role
	invites         map[string]Invite
	rotationPending bool
}

// Empty is the state before any room exists - the only entry Apply will accept from here is a
// genesis.
func Empty() *State {
	return &State{
		roomID:   make([]byte, 32),
		headHash: make([]byte, 32),
		roles:    map[string]Role{},
		invites:  map[string]Invite{},
	}
}

func (s *State) RoomID() []byte        { return s.roomID }
func (s *State) HeadHash() []byte      { return s.headHash }
func (s *State) NextIndex() uint64     { return s.nextIndex }
func (s *State) Epoch() uint64         { return s.epoch }
func (s *State) RotationPending() bool { return s.rotationPending }

func (s *State) RoleOf(user []byte) (Role, bool) {
	r, ok := s.roles[hexKey(user)]
	return r, ok
}

func (s *State) Invites() []Invite {
	out := make([]Invite, 0, len(s.invites))
	for _, inv := range s.invites {
		out = append(out, inv)
	}
	return out
}

func hexKey(b []byte) string { return hex.EncodeToString(b) }

// Apply validates stored.Entry against the current state and returns the next state, or a
// RejectReason error describing which §3.3 rule failed.
func (s *State) Apply(stored StoredEntry) (*State, error) {
	entry := stored.Entry
	if !entry.Verify() {
		return nil, reject("BadSignature")
	}
	if entry.Index != s.nextIndex {
		return nil, reject("BadChain")
	}

	if s.nextIndex == 0 {
		return s.applyGenesis(entry)
	}

	if !bytes.Equal(entry.Room, s.roomID) {
		return nil, invalid("room id mismatch")
	}
	if entry.Prev == nil || !bytes.Equal(entry.Prev, s.headHash) {
		return nil, reject("BadChain")
	}

	authorRole, hasAuthorRole := s.RoleOf(entry.Author)

	switch entry.Type {
	case proto.EntryGenesis:
		return nil, invalid("genesis only valid at index 0")
	case proto.EntryInviteCreate:
		return s.applyInviteCreate(entry, authorRole, hasAuthorRole)
	case proto.EntryInviteRevoke:
		return s.applyInviteRevoke(entry, authorRole, hasAuthorRole)
	case proto.EntryJoin:
		return s.applyJoin(entry, stored.Rts)
	case proto.EntryApprove:
		return s.applyApproveOrReject(entry, authorRole, hasAuthorRole, true)
	case proto.EntryReject:
		return s.applyApproveOrReject(entry, authorRole, hasAuthorRole, false)
	case proto.EntryRemove:
		return s.applyRemove(entry, authorRole, hasAuthorRole)
	case proto.EntryLeave:
		return s.applyLeave(entry, authorRole, hasAuthorRole)
	case proto.EntrySetRole:
		return s.applySetRole(entry, authorRole, hasAuthorRole)
	case proto.EntryTransferOwner:
		return s.applyTransferOwner(entry, authorRole, hasAuthorRole)
	case proto.EntryEpochRotate:
		return s.applyEpochRotate(entry, authorRole, hasAuthorRole)
	case proto.EntryRoomSettings:
		return s.applyRoomSettings(entry, authorRole, hasAuthorRole)
	default:
		return nil, invalid("unknown entry type")
	}
}

// ---- §3.3 row 0 ----

func (s *State) applyGenesis(entry proto.LogEntry) (*State, error) {
	if entry.Type != proto.EntryGenesis {
		return nil, invalid("first entry must be genesis")
	}
	if entry.Prev != nil {
		return nil, reject("BadChain")
	}
	nonce, ok := bodyBytes(entry.Body, 0)
	if !ok {
		return nil, invalid("genesis missing roomNonce")
	}
	expectedRoomID := RoomID(entry.Author, nonce)
	if !bytes.Equal(expectedRoomID, entry.Room) {
		return nil, invalid("roomId does not match author+nonce")
	}
	roles := map[string]Role{hexKey(entry.Author): RoleOwner}
	return s.next(entry, roles, s.invites, s.epoch, false)
}

// ---- §3.3 row 1/2: invites ----

func (s *State) applyInviteCreate(entry proto.LogEntry, authorRole Role, has bool) (*State, error) {
	if !has || (authorRole != RoleOwner && authorRole != RoleAdmin) {
		return nil, reject("Unauthorized")
	}
	inviteID, ok := bodyBytes(entry.Body, 0)
	if !ok {
		return nil, invalid("inviteCreate missing inviteId")
	}
	idHex := hexKey(inviteID)
	if _, exists := s.invites[idHex]; exists {
		return nil, invalid("invite id already exists")
	}
	requiresApproval, ok := bodyBool(entry.Body, 3)
	if !ok {
		return nil, invalid("inviteCreate missing requiresApproval")
	}
	role, ok := bodyText(entry.Body, 4)
	if !ok {
		return nil, invalid("inviteCreate missing role")
	}
	if role != "member" {
		return nil, invalid("inviteCreate role must be \"member\", was '" + role + "'")
	}
	inv := Invite{ID: inviteID, RequiresApproval: requiresApproval}
	if expiresAt, ok := bodyUint(entry.Body, 1); ok {
		inv.ExpiresAt = &expiresAt
	}
	if maxUses, ok := bodyUint(entry.Body, 2); ok {
		n := int(maxUses)
		inv.MaxUses = &n
	}
	invites := cloneInvites(s.invites)
	invites[idHex] = inv
	return s.next(entry, s.roles, invites, s.epoch, s.rotationPending)
}

func (s *State) applyInviteRevoke(entry proto.LogEntry, authorRole Role, has bool) (*State, error) {
	if !has || (authorRole != RoleOwner && authorRole != RoleAdmin) {
		return nil, reject("Unauthorized")
	}
	inviteID, ok := bodyBytes(entry.Body, 0)
	if !ok {
		return nil, invalid("inviteRevoke missing inviteId")
	}
	idHex := hexKey(inviteID)
	inv, exists := s.invites[idHex]
	if !exists {
		return nil, invalid("invite not found")
	}
	inv.Revoked = true
	invites := cloneInvites(s.invites)
	invites[idHex] = inv
	return s.next(entry, s.roles, invites, s.epoch, s.rotationPending)
}

// ---- §3.3 row 3: join ----

func (s *State) applyJoin(entry proto.LogEntry, rts uint64) (*State, error) {
	authorHex := hexKey(entry.Author)
	if _, exists := s.roles[authorHex]; exists {
		return nil, invalid("already a member")
	}
	inviteID, ok := bodyBytes(entry.Body, 0)
	if !ok {
		return nil, invalid("join missing inviteId")
	}
	idHex := hexKey(inviteID)
	inv, exists := s.invites[idHex]
	if !exists {
		return nil, invalid("invite not found")
	}
	if inv.Revoked {
		return nil, reject("InviteRevoked")
	}
	if inv.ExpiresAt != nil && rts >= *inv.ExpiresAt {
		return nil, reject("InviteExpired")
	}
	if inv.MaxUses != nil && inv.Uses >= *inv.MaxUses {
		return nil, reject("InviteExhausted")
	}
	newRole := RoleMember
	if inv.RequiresApproval {
		newRole = RolePending
	}
	inv.Uses++
	roles := cloneRoles(s.roles)
	roles[authorHex] = newRole
	invites := cloneInvites(s.invites)
	invites[idHex] = inv
	return s.next(entry, roles, invites, s.epoch, s.rotationPending)
}

// ---- §3.3 row 4/5: approve/reject ----

func (s *State) applyApproveOrReject(entry proto.LogEntry, authorRole Role, has bool, approve bool) (*State, error) {
	if !has || (authorRole != RoleOwner && authorRole != RoleAdmin) {
		return nil, reject("Unauthorized")
	}
	target, ok := bodyBytes(entry.Body, 0)
	if !ok {
		return nil, invalid("missing target user")
	}
	targetHex := hexKey(target)
	targetRole, exists := s.roles[targetHex]
	if !exists || targetRole != RolePending {
		return nil, invalid("target is not pending")
	}
	roles := cloneRoles(s.roles)
	if approve {
		if _, ok := bodyBytes(entry.Body, 1); !ok {
			return nil, invalid("approve missing wrappedEpochKey")
		}
		roles[targetHex] = RoleMember
	} else {
		delete(roles, targetHex)
	}
	return s.next(entry, roles, s.invites, s.epoch, s.rotationPending)
}

// ---- §3.3 row 6: remove ----

func (s *State) applyRemove(entry proto.LogEntry, authorRole Role, hasAuthorRole bool) (*State, error) {
	target, ok := bodyBytes(entry.Body, 0)
	if !ok {
		return nil, invalid("remove missing target user")
	}
	targetHex := hexKey(target)
	targetRole, exists := s.roles[targetHex]
	if !exists {
		return nil, invalid("target is not a member")
	}
	if !hasAuthorRole {
		return nil, reject("Unauthorized")
	}
	switch authorRole {
	case RoleOwner:
		if bytes.Equal(target, entry.Author) {
			return nil, invalid("owner cannot remove self")
		}
	case RoleAdmin:
		if targetRole != RoleMember {
			return nil, reject("Unauthorized")
		}
	default:
		return nil, reject("Unauthorized")
	}
	roles := cloneRoles(s.roles)
	delete(roles, targetHex)
	return s.next(entry, roles, s.invites, s.epoch, true)
}

// ---- §3.3 row 7: leave ----

func (s *State) applyLeave(entry proto.LogEntry, authorRole Role, hasAuthorRole bool) (*State, error) {
	if !hasAuthorRole {
		return nil, reject("Unauthorized")
	}
	switch authorRole {
	case RoleMember, RoleAdmin:
		// ok
	case RoleOwner:
		return nil, invalid("owner must transferOwner before leaving")
	default:
		return nil, reject("Unauthorized")
	}
	roles := cloneRoles(s.roles)
	delete(roles, hexKey(entry.Author))
	return s.next(entry, roles, s.invites, s.epoch, s.rotationPending)
}

// ---- §3.3 row 8: setRole ----

func (s *State) applySetRole(entry proto.LogEntry, authorRole Role, hasAuthorRole bool) (*State, error) {
	if !hasAuthorRole || authorRole != RoleOwner {
		return nil, reject("Unauthorized")
	}
	target, ok := bodyBytes(entry.Body, 0)
	if !ok {
		return nil, invalid("setRole missing target user")
	}
	targetHex := hexKey(target)
	roleText, ok := bodyText(entry.Body, 1)
	if !ok {
		return nil, invalid("setRole missing role")
	}
	var newRole Role
	switch roleText {
	case "admin":
		newRole = RoleAdmin
	case "member":
		newRole = RoleMember
	default:
		return nil, invalid("role must be admin or member, was '" + roleText + "'")
	}
	targetRole, exists := s.roles[targetHex]
	if !exists {
		return nil, invalid("target is not a member")
	}
	switch targetRole {
	case RolePending:
		return nil, invalid("target is pending, approve or reject first")
	case RoleOwner:
		return nil, invalid("target is the owner, use transferOwner")
	}
	roles := cloneRoles(s.roles)
	roles[targetHex] = newRole
	return s.next(entry, roles, s.invites, s.epoch, s.rotationPending)
}

// ---- §3.3 row 9: transferOwner ----

func (s *State) applyTransferOwner(entry proto.LogEntry, authorRole Role, hasAuthorRole bool) (*State, error) {
	if !hasAuthorRole || authorRole != RoleOwner {
		return nil, reject("Unauthorized")
	}
	target, ok := bodyBytes(entry.Body, 0)
	if !ok {
		return nil, invalid("transferOwner missing target user")
	}
	targetHex := hexKey(target)
	if targetRole, exists := s.roles[targetHex]; !exists || targetRole != RoleAdmin {
		return nil, invalid("transferOwner target must currently be admin")
	}
	roles := cloneRoles(s.roles)
	roles[hexKey(entry.Author)] = RoleAdmin
	roles[targetHex] = RoleOwner
	return s.next(entry, roles, s.invites, s.epoch, s.rotationPending)
}

// ---- §3.3 row 10: epochRotate ----

func (s *State) applyEpochRotate(entry proto.LogEntry, authorRole Role, hasAuthorRole bool) (*State, error) {
	if !hasAuthorRole || (authorRole != RoleOwner && authorRole != RoleAdmin) {
		return nil, reject("Unauthorized")
	}
	newEpoch, ok := bodyUint(entry.Body, 0)
	if !ok {
		return nil, invalid("epochRotate missing epoch")
	}
	if newEpoch != s.epoch+1 {
		return nil, invalid("epoch must increase by exactly 1")
	}
	wrapped, ok := bodyArray(entry.Body, 1)
	if !ok {
		return nil, invalid("epochRotate missing wrapped key list")
	}
	listedUsers := make([]string, 0, len(wrapped))
	seen := map[string]bool{}
	for _, item := range wrapped {
		user, ok := itemMapBytes(item, 0)
		if !ok {
			return nil, invalid("epochRotate entry missing user")
		}
		if _, ok := itemMapBytes(item, 1); !ok {
			return nil, invalid("epochRotate entry missing sealedKey")
		}
		userHex := hexKey(user)
		if seen[userHex] {
			return nil, invalid("epochRotate lists the same user more than once")
		}
		seen[userHex] = true
		listedUsers = append(listedUsers, userHex)
	}
	currentNonPending := map[string]bool{}
	for userHex, role := range s.roles {
		if role != RolePending {
			currentNonPending[userHex] = true
		}
	}
	if len(listedUsers) != len(currentNonPending) {
		return nil, invalid("epochRotate must contain exactly the current non-pending members")
	}
	for _, userHex := range listedUsers {
		if !currentNonPending[userHex] {
			return nil, invalid("epochRotate must contain exactly the current non-pending members")
		}
	}
	return s.next(entry, s.roles, s.invites, newEpoch, false)
}

// ---- §3.3 row 11: roomSettings ----

func (s *State) applyRoomSettings(entry proto.LogEntry, authorRole Role, hasAuthorRole bool) (*State, error) {
	if !hasAuthorRole || (authorRole != RoleOwner && authorRole != RoleAdmin) {
		return nil, reject("Unauthorized")
	}
	return s.next(entry, s.roles, s.invites, s.epoch, s.rotationPending)
}

// ---- plumbing ----

func (s *State) next(entry proto.LogEntry, roles map[string]Role, invites map[string]Invite, epoch uint64, rotationPending bool) (*State, error) {
	return &State{
		roomID:          entry.Room,
		headHash:        entry.EntryHash(),
		nextIndex:       entry.Index + 1,
		epoch:           epoch,
		roles:           roles,
		invites:         invites,
		rotationPending: rotationPending,
	}, nil
}

func cloneRoles(m map[string]Role) map[string]Role {
	out := make(map[string]Role, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneInvites(m map[string]Invite) map[string]Invite {
	out := make(map[string]Invite, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ---- body accessors (entry.Body is map[uint64]any, decoded by fxamacker/cbor; nested CBOR maps
// inside an array - epochRotate's wrapped-key list - decode to map[any]any, see itemMapBytes) ----

func bodyBytes(body map[uint64]any, key uint64) ([]byte, bool) {
	v, ok := body[key]
	if !ok {
		return nil, false
	}
	b, ok := v.([]byte)
	return b, ok
}

func bodyUint(body map[uint64]any, key uint64) (uint64, bool) {
	v, ok := body[key]
	if !ok {
		return 0, false
	}
	u, ok := v.(uint64)
	return u, ok
}

func bodyText(body map[uint64]any, key uint64) (string, bool) {
	v, ok := body[key]
	if !ok {
		return "", false
	}
	t, ok := v.(string)
	return t, ok
}

func bodyBool(body map[uint64]any, key uint64) (bool, bool) {
	v, ok := body[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

func bodyArray(body map[uint64]any, key uint64) ([]any, bool) {
	v, ok := body[key]
	if !ok {
		return nil, false
	}
	a, ok := v.([]any)
	return a, ok
}

func itemMapBytes(item any, key uint64) ([]byte, bool) {
	m, ok := item.(map[any]any)
	if !ok {
		return nil, false
	}
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	b, ok := v.([]byte)
	return b, ok
}
