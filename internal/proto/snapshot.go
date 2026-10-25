package proto

// SnapshotDomain is the signing domain for Snapshot (PROTOCOL.md §4.4).
const SnapshotDomain = "snapshot"

// Snapshot mirrors PROTOCOL.md §4.4 field-for-field. Signed by the *device* key named in Device
// (field 7), not the user key - same pattern as OpEnvelope and LogEntry.
//
// The relay never decrypts Ct and never computes the AEAD associated data itself (that's the
// client's job before/after this structure exists) - it only verifies the outer signature (domain
// "snapshot", over fields 0..7) and, once decoded, can read CoversUpTo in the clear to drive
// retention pruning (PROTOCOL.md §4.4's "relay MAY prune ops ... 30 days after a snapshot
// exists").
type Snapshot struct {
	V          uint64 `cbor:"0,keyasint"`
	Room       []byte `cbor:"1,keyasint"`
	Epoch      uint64 `cbor:"2,keyasint"`
	CoversUpTo uint64 `cbor:"3,keyasint"`
	Nonce      []byte `cbor:"4,keyasint"`
	Ct         []byte `cbor:"5,keyasint"`
	Author     []byte `cbor:"6,keyasint"`
	Device     []byte `cbor:"7,keyasint"`
	Sig        []byte `cbor:"8,keyasint,omitempty"`
}

// DecodeSnapshot decodes and rejects anything that is not canonical CBOR (PROTOCOL.md §1).
// Does not itself verify the signature - call Verify() for that.
func DecodeSnapshot(data []byte) (*Snapshot, error) {
	var s Snapshot
	if err := DecodeCanonicalInto(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// AdCbor is fields 0..4 (v, room, epoch, coversUpTo, nonce) - the AEAD associated data for Ct,
// PROTOCOL.md §4.4: "ad = CBOR(fields 0..4)", analogous to OpEnvelope's ad.
func (s Snapshot) AdCbor() ([]byte, error) {
	ad := struct {
		V          uint64 `cbor:"0,keyasint"`
		Room       []byte `cbor:"1,keyasint"`
		Epoch      uint64 `cbor:"2,keyasint"`
		CoversUpTo uint64 `cbor:"3,keyasint"`
		Nonce      []byte `cbor:"4,keyasint"`
	}{s.V, s.Room, s.Epoch, s.CoversUpTo, s.Nonce}
	return EncodeCanonical(ad)
}

// unsignedCbor is fields 0..7, i.e. the struct without Sig - exactly what is signed over.
func (s Snapshot) unsignedCbor() ([]byte, error) {
	s.Sig = nil
	return EncodeCanonical(s)
}

// FullCbor is all fields 0..8 incl. Sig - the complete signed structure as it travels on the wire.
func (s Snapshot) FullCbor() ([]byte, error) {
	return EncodeCanonical(s)
}

// Verify is self-contained crypto/structural validity only: known version and a valid Ed25519
// signature by Device under domain "snapshot". It does NOT check that Device actually belongs to
// Author - that needs a /users/{u}/devices lookup the relay performs separately, same limitation
// as OpEnvelope.
func (s Snapshot) Verify() bool {
	if s.Sig == nil || s.V != 1 {
		return false
	}
	unsigned, err := s.unsignedCbor()
	if err != nil {
		return false
	}
	return Ed25519Verify(s.Device, SigningInput(SnapshotDomain, unsigned), s.Sig)
}
