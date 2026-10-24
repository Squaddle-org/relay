package membership

import "github.com/squaddle-org/relay/internal/proto"

// Role, PROTOCOL.md §3.3: "owner (exactly one) > admin > member; pending has no read access."
type Role int

const (
	RoleOwner Role = iota
	RoleAdmin
	RoleMember
	RolePending
)

func (r Role) String() string {
	switch r {
	case RoleOwner:
		return "owner"
	case RoleAdmin:
		return "admin"
	case RoleMember:
		return "member"
	case RolePending:
		return "pending"
	default:
		return "unknown"
	}
}

// Invite mirrors core's membership/MembershipLog.kt Invite - immutable by convention (Apply
// always returns a *new* State with a *new* Invite value, never mutates one in place).
type Invite struct {
	ID               []byte
	ExpiresAt        *uint64
	MaxUses          *int
	RequiresApproval bool
	Uses             int
	Revoked          bool
}

// StoredEntry pairs a LogEntry with the relay-assigned timestamp, which travels next to the
// entry and is never part of what's signed (PROTOCOL.md §3.2).
type StoredEntry struct {
	Entry proto.LogEntry
	Rts   uint64
}

// RejectReason carries *which* §3.3 rule an Apply() call failed, as an error. Matches core's
// sealed RejectReason shape closely enough for readable test output; vectors only check the
// accept/reject outcome, not this string, so there's no need for byte-exact parity with Kotlin.
type RejectReason struct {
	Code string // "BadSignature" | "BadChain" | "Unauthorized" | "InviteExpired" | "InviteExhausted" | "InviteRevoked" | "Invalid"
	Why  string // only set when Code == "Invalid"
}

func (r RejectReason) Error() string {
	if r.Code == "Invalid" {
		return "Invalid(why=" + r.Why + ")"
	}
	return r.Code
}

func reject(code string) error { return RejectReason{Code: code} }
func invalid(why string) error { return RejectReason{Code: "Invalid", Why: why} }
