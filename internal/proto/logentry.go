package proto

import "bytes"

// LogEntryDomain is the signing domain for LogEntry (PROTOCOL.md §3.2).
const LogEntryDomain = "logentry"

// EntryType codes, PROTOCOL.md §3.3.
const (
	EntryGenesis       uint64 = 0
	EntryInviteCreate  uint64 = 1
	EntryInviteRevoke  uint64 = 2
	EntryJoin          uint64 = 3
	EntryApprove       uint64 = 4
	EntryReject        uint64 = 5
	EntryRemove        uint64 = 6
	EntryLeave         uint64 = 7
	EntrySetRole       uint64 = 8
	EntryTransferOwner uint64 = 9
	EntryEpochRotate   uint64 = 10
	EntryRoomSettings  uint64 = 11
)

// LogEntry mirrors core's membership/MembershipLog.kt LogEntry field-for-field (PROTOCOL.md
// §3.2). Body is a generic int-keyed map, same as core's CborValue.Map - every §3.3 body is one.
type LogEntry struct {
	V      uint64         `cbor:"0,keyasint"`
	Room   []byte         `cbor:"1,keyasint"`
	Index  uint64         `cbor:"2,keyasint"`
	Prev   []byte         `cbor:"3,keyasint,omitempty"`
	Author []byte         `cbor:"4,keyasint"`
	Cert   DeviceCert     `cbor:"5,keyasint"`
	Type   uint64         `cbor:"6,keyasint"`
	Body   map[uint64]any `cbor:"7,keyasint"`
	Ts     uint64         `cbor:"8,keyasint"`
	Sig    []byte         `cbor:"9,keyasint,omitempty"`
}

// DecodeLogEntry decodes and rejects anything that is not canonical CBOR (PROTOCOL.md §1). Does
// not itself verify the signature/chain - call Verify() and (for chain/authorization) package
// membership's state machine for that.
func DecodeLogEntry(data []byte) (*LogEntry, error) {
	var e LogEntry
	if err := DecodeCanonicalInto(data, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// unsignedCbor is fields 0..8, i.e. the struct without Sig - exactly what is signed over.
func (e LogEntry) unsignedCbor() ([]byte, error) {
	e.Sig = nil
	return EncodeCanonical(e)
}

// FullCbor is all fields 0..9 incl. Sig - what EntryHash is computed over and what travels on
// the wire.
func (e LogEntry) FullCbor() ([]byte, error) {
	return EncodeCanonical(e)
}

// EntryHash is `BLAKE2b(CBOR(full entry incl. sig))` (PROTOCOL.md §3.2) - a plain hash, not the
// domain-separated SigningInput construction (that's for the signature itself).
func (e LogEntry) EntryHash() []byte {
	full, err := e.FullCbor()
	if err != nil {
		// Only reachable for a LogEntry this package itself built from well-typed Go values
		// (byte slices, uints, a map[uint64]any) - DecodeLogEntry already validates incoming
		// untrusted bytes before producing one, so there is nothing left here that can fail.
		panic(err)
	}
	return Blake2b256(full)
}

// Verify is self-contained crypto/structural validity: known version, Cert itself valid, Cert's
// claimed user matches Author, and Sig verifies under Cert's *device* key (not the user key -
// PROTOCOL.md §3.2 field 9: the device named in the entry's own embedded cert signs the entry).
// Chain and §3.3 authorization rules need sequence context this single entry doesn't have - see
// package membership.
func (e LogEntry) Verify() bool {
	if e.Sig == nil {
		return false
	}
	if e.V != 1 {
		return false
	}
	if !e.Cert.Verify() {
		return false
	}
	if !bytes.Equal(e.Cert.User, e.Author) {
		return false
	}
	unsigned, err := e.unsignedCbor()
	if err != nil {
		return false
	}
	return Ed25519Verify(e.Cert.Device, SigningInput(LogEntryDomain, unsigned), e.Sig)
}
