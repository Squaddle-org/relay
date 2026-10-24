package proto

// DeviceRevokeDomain is the signing domain for DeviceRevoke (PROTOCOL.md §2.2).
const DeviceRevokeDomain = "devrevoke"

// DeviceRevoke mirrors PROTOCOL.md §2.2: `DeviceRevoke { 0:v, 1:user, 2:device, 3:revokedAt,
// 4:sig }`, signed by the *user* signing key (unlike DeviceCert/LogEntry, which are signed by a
// device key). Not yet implemented in core - this only matters once the relay actually serves
// `GET /users/{user}/devices` with revocations included (relay-api.yaml), so it lives here first.
// No test vector governs it (no devicerevoke.json exists).
type DeviceRevoke struct {
	V         uint64 `cbor:"0,keyasint"`
	User      []byte `cbor:"1,keyasint"`
	Device    []byte `cbor:"2,keyasint"`
	RevokedAt uint64 `cbor:"3,keyasint"`
	Sig       []byte `cbor:"4,keyasint,omitempty"`
}

// DecodeDeviceRevoke decodes and rejects anything that is not canonical CBOR (PROTOCOL.md §1).
func DecodeDeviceRevoke(data []byte) (*DeviceRevoke, error) {
	var r DeviceRevoke
	if err := DecodeCanonicalInto(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r DeviceRevoke) unsignedCbor() ([]byte, error) {
	r.Sig = nil
	return EncodeCanonical(r)
}

// FullCbor is all fields 0..4 incl. Sig.
func (r DeviceRevoke) FullCbor() ([]byte, error) {
	return EncodeCanonical(r)
}

// Verify checks known version and a valid Ed25519 signature by User under domain "devrevoke".
func (r DeviceRevoke) Verify() bool {
	if r.Sig == nil || r.V != 1 {
		return false
	}
	unsigned, err := r.unsignedCbor()
	if err != nil {
		return false
	}
	return Ed25519Verify(r.User, SigningInput(DeviceRevokeDomain, unsigned), r.Sig)
}
