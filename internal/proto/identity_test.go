package proto

import (
	"bytes"
	"testing"
)

// TestIdentityVectors is the Go side of the cross-implementation test for PROTOCOL.md §2.1.
func TestIdentityVectors(t *testing.T) {
	for _, v := range loadVectors(t, "identity.json") {
		name := vstr(v, "name")
		input := vobj(v, "input")
		expected := vobj(v, "expected")

		if accept, ok := vbool(expected, "accept"); ok && !accept {
			if _, err := MnemonicToEntropy(vstrings(input, "mnemonic")); err == nil {
				t.Errorf("%s: expected reject, but MnemonicToEntropy succeeded", name)
			}
			continue
		}

		entropy := vbytes(t, input, "entropy")
		identity := DeriveUserIdentity(entropy)

		mnemonic, err := EntropyToMnemonic(entropy)
		if err != nil {
			t.Fatalf("%s: EntropyToMnemonic: %v", name, err)
		}
		if expectedMnemonic := vstrings(expected, "mnemonic"); !stringsEqual(mnemonic, expectedMnemonic) {
			t.Errorf("%s: mnemonic = %v, want %v", name, mnemonic, expectedMnemonic)
		}
		if !bytes.Equal(Blake2b256(entropy), vbytes(t, expected, "master")) {
			t.Errorf("%s: master mismatch", name)
		}
		if !bytes.Equal(identity.UserKey, vbytes(t, expected, "userKey")) {
			t.Errorf("%s: userKey mismatch", name)
		}
		if !bytes.Equal(identity.UserBoxKey, vbytes(t, expected, "userBoxKey")) {
			t.Errorf("%s: userBoxKey mismatch", name)
		}
		if !bytes.Equal(identity.BackupKey, vbytes(t, expected, "backupKey")) {
			t.Errorf("%s: backupKey mismatch", name)
		}
	}
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
