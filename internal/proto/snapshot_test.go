package proto

import (
	"bytes"
	"testing"
)

// TestSnapshotVectors is the Go side of the cross-implementation test for PROTOCOL.md §4.4.
func TestSnapshotVectors(t *testing.T) {
	for _, v := range loadVectors(t, "snapshot.json") {
		name := vstr(v, "name")
		input := vobj(v, "input")
		expected := vobj(v, "expected")
		accept, _ := vbool(expected, "accept")

		if !accept {
			snap, err := DecodeSnapshot(vbytes(t, input, "cbor"))
			if err != nil {
				t.Errorf("%s: DecodeSnapshot: %v", name, err)
				continue
			}
			if snap.Verify() {
				t.Errorf("%s: expected reject, but Verify() returned true", name)
			}
			continue
		}

		snap, err := DecodeSnapshot(vbytes(t, expected, "cbor"))
		if err != nil {
			t.Fatalf("%s: DecodeSnapshot: %v", name, err)
		}
		if !snap.Verify() {
			t.Errorf("%s: expected accept, but Verify() returned false", name)
		}
		if !bytes.Equal(snap.Room, vbytes(t, input, "room")) {
			t.Errorf("%s: room mismatch", name)
		}
		if wantEpoch, ok := input["epoch"].(float64); ok && snap.Epoch != uint64(wantEpoch) {
			t.Errorf("%s: epoch = %d, want %d", name, snap.Epoch, uint64(wantEpoch))
		}
		if wantCoversUpTo, ok := input["coversUpTo"].(float64); ok && snap.CoversUpTo != uint64(wantCoversUpTo) {
			t.Errorf("%s: coversUpTo = %d, want %d", name, snap.CoversUpTo, uint64(wantCoversUpTo))
		}
		if !bytes.Equal(snap.Nonce, vbytes(t, input, "nonce")) {
			t.Errorf("%s: nonce mismatch", name)
		}
		if !bytes.Equal(snap.Ct, vbytes(t, input, "ct")) {
			t.Errorf("%s: ct mismatch", name)
		}
		if !bytes.Equal(snap.Author, vbytes(t, input, "author")) {
			t.Errorf("%s: author mismatch", name)
		}
		if !bytes.Equal(snap.Device, vbytes(t, input, "device")) {
			t.Errorf("%s: device mismatch", name)
		}
		if !bytes.Equal(snap.Sig, vbytes(t, expected, "sig")) {
			t.Errorf("%s: sig mismatch", name)
		}

		ad, err := snap.AdCbor()
		if err != nil {
			t.Fatalf("%s: AdCbor: %v", name, err)
		}
		if !bytes.Equal(ad, vbytes(t, expected, "ad")) {
			t.Errorf("%s: ad mismatch", name)
		}

		unsigned, err := snap.unsignedCbor()
		if err != nil {
			t.Fatalf("%s: unsignedCbor: %v", name, err)
		}
		if !bytes.Equal(unsigned, vbytes(t, expected, "unsignedCbor")) {
			t.Errorf("%s: unsignedCbor mismatch", name)
		}
		if !bytes.Equal(SigningInput(SnapshotDomain, unsigned), vbytes(t, expected, "signingInput")) {
			t.Errorf("%s: signingInput mismatch", name)
		}
	}
}
