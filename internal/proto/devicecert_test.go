package proto

import (
	"bytes"
	"testing"
)

// TestDeviceCertVectors is the Go side of the cross-implementation test for PROTOCOL.md §2.2.
func TestDeviceCertVectors(t *testing.T) {
	for _, v := range loadVectors(t, "devicecert.json") {
		name := vstr(v, "name")
		input := vobj(v, "input")
		expected := vobj(v, "expected")
		accept, _ := vbool(expected, "accept")

		if !accept {
			cert, err := DecodeDeviceCert(vbytes(t, input, "cbor"))
			if err != nil {
				t.Errorf("%s: DecodeDeviceCert: %v", name, err)
				continue
			}
			if cert.Verify() {
				t.Errorf("%s: expected reject, but Verify() returned true", name)
			}
			continue
		}

		cert, err := DecodeDeviceCert(vbytes(t, expected, "cbor"))
		if err != nil {
			t.Fatalf("%s: DecodeDeviceCert: %v", name, err)
		}
		if !cert.Verify() {
			t.Errorf("%s: expected accept, but Verify() returned false", name)
		}
		if cert.Label != vstr(input, "label") {
			t.Errorf("%s: label = %q, want %q", name, cert.Label, vstr(input, "label"))
		}
		if !bytes.Equal(cert.User, vbytes(t, input, "user")) {
			t.Errorf("%s: user mismatch", name)
		}
		if !bytes.Equal(cert.UserBox, vbytes(t, input, "userBox")) {
			t.Errorf("%s: userBox mismatch", name)
		}
		if !bytes.Equal(cert.Device, vbytes(t, input, "device")) {
			t.Errorf("%s: device mismatch", name)
		}
		if !bytes.Equal(cert.Sig, vbytes(t, expected, "sig")) {
			t.Errorf("%s: sig mismatch", name)
		}
		unsigned, err := cert.unsignedCbor()
		if err != nil {
			t.Fatalf("%s: unsignedCbor: %v", name, err)
		}
		if !bytes.Equal(unsigned, vbytes(t, expected, "unsignedCbor")) {
			t.Errorf("%s: unsignedCbor mismatch", name)
		}
		if !bytes.Equal(SigningInput(DeviceCertDomain, unsigned), vbytes(t, expected, "signingInput")) {
			t.Errorf("%s: signingInput mismatch", name)
		}
	}
}
