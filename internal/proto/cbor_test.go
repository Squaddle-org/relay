package proto

import "testing"

// TestCborRejectVectors is the Go side of the cross-implementation test (PROTOCOL.md §1): every
// accept/reject case core (Kotlin) generated must agree with DecodeCanonical.
func TestCborRejectVectors(t *testing.T) {
	for _, v := range loadVectors(t, "cbor-reject.json") {
		name := vstr(v, "name")
		data := vbytes(t, vobj(v, "input"), "cbor")
		accept, _ := vbool(vobj(v, "expected"), "accept")

		_, err := DecodeCanonical(data)
		switch {
		case accept && err != nil:
			t.Errorf("%s: expected accept, got error: %v", name, err)
		case !accept && err == nil:
			t.Errorf("%s: expected reject, but decoded successfully", name)
		}
	}
}
