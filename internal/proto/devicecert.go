package proto

// DeviceCertDomain is the signing domain for DeviceCert (PROTOCOL.md §2.2).
const DeviceCertDomain = "devcert"

// MaxLabelLength is DeviceCert.Label's limit (PROTOCOL.md §2.2: "max 64 chars").
const MaxLabelLength = 64

// DeviceCert mirrors core's identity/DeviceCert.kt field-for-field (PROTOCOL.md §2.2). Struct
// fields are declared in ascending key order on purpose - matters for canonical encoding.
type DeviceCert struct {
	V        uint64 `cbor:"0,keyasint"`
	User     []byte `cbor:"1,keyasint"`
	UserBox  []byte `cbor:"2,keyasint"`
	Device   []byte `cbor:"3,keyasint"`
	Label    string `cbor:"4,keyasint"`
	IssuedAt uint64 `cbor:"5,keyasint"`
	Sig      []byte `cbor:"6,keyasint,omitempty"`
}

// DecodeDeviceCert decodes and rejects anything that is not canonical CBOR (PROTOCOL.md §1).
// Does not itself verify the signature - call Verify() for that.
func DecodeDeviceCert(data []byte) (*DeviceCert, error) {
	var c DeviceCert
	if err := DecodeCanonicalInto(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// unsignedCbor is fields 0..5, i.e. the struct without Sig - exactly what is signed over.
func (c DeviceCert) unsignedCbor() ([]byte, error) {
	c.Sig = nil
	return EncodeCanonical(c)
}

// FullCbor is all fields 0..6 incl. Sig - the complete signed structure as it travels on the wire.
func (c DeviceCert) FullCbor() ([]byte, error) {
	return EncodeCanonical(c)
}

// Verify checks: Sig present, known version, label within the length limit, and a valid Ed25519
// signature by User under domain "devcert" - all three structural checks apply even if the
// signature itself would otherwise verify (PROTOCOL.md §2.2/§9).
func (c DeviceCert) Verify() bool {
	if c.Sig == nil {
		return false
	}
	if c.V != 1 {
		return false
	}
	if len(c.Label) > MaxLabelLength {
		return false
	}
	unsigned, err := c.unsignedCbor()
	if err != nil {
		return false
	}
	return Ed25519Verify(c.User, SigningInput(DeviceCertDomain, unsigned), c.Sig)
}
