package membership

import (
	"bytes"
	"testing"

	"github.com/squaddle-org/relay/internal/proto"
)

// TestLogEntryVectors replays logentry.json's chain and checks entryHash + rotationPending
// (ADR-0012) at every step - the Go side of the cross-implementation test for PROTOCOL.md §3.2/§3.3.
func TestLogEntryVectors(t *testing.T) {
	for _, v := range loadVectors(t, "logentry.json") {
		name := vstr(v, "name")
		input := vobj(v, "input")
		expected := vobj(v, "expected")
		expectedRoomID := vbytes(t, input, "room")

		state := Empty()
		for _, raw := range varr(expected, "entries") {
			step, _ := raw.(map[string]any)
			entry, err := proto.DecodeLogEntry(vbytes(t, step, "cbor"))
			if err != nil {
				t.Fatalf("%s: DecodeLogEntry: %v", name, err)
			}
			next, err := state.Apply(StoredEntry{Entry: *entry, Rts: 1_700_000_500})
			if err != nil {
				t.Fatalf("%s: index %d: Apply: %v", name, entry.Index, err)
			}
			state = next

			if !bytes.Equal(entry.EntryHash(), vbytes(t, step, "entryHash")) {
				t.Errorf("%s: index %d: entryHash mismatch", name, entry.Index)
			}
			wantRotation, _ := vbool(step, "rotationPending")
			if state.RotationPending() != wantRotation {
				t.Errorf("%s: index %d: rotationPending = %v, want %v", name, entry.Index, state.RotationPending(), wantRotation)
			}
		}
		if !bytes.Equal(state.RoomID(), expectedRoomID) {
			t.Errorf("%s: final roomID mismatch", name)
		}
	}
}

// TestLogRejectVectors replays each vector's valid prefix, then confirms the final entry is
// rejected - one case per §3.3 row plus the chain-level stale-head case (13 total).
func TestLogRejectVectors(t *testing.T) {
	for _, v := range loadVectors(t, "log-reject.json") {
		name := vstr(v, "name")
		input := vobj(v, "input")
		expected := vobj(v, "expected")

		state := Empty()
		for _, raw := range varr(input, "prefix") {
			s, _ := raw.(string)
			entry, err := proto.DecodeLogEntry(b64(t, s))
			if err != nil {
				t.Fatalf("%s: DecodeLogEntry (prefix): %v", name, err)
			}
			next, err := state.Apply(StoredEntry{Entry: *entry, Rts: 1_700_000_500})
			if err != nil {
				t.Fatalf("%s: prefix entry index %d unexpectedly rejected: %v", name, entry.Index, err)
			}
			state = next
		}

		badEntry, err := proto.DecodeLogEntry(vbytes(t, input, "entry"))
		if err != nil {
			t.Fatalf("%s: DecodeLogEntry (bad entry): %v", name, err)
		}
		_, applyErr := state.Apply(StoredEntry{Entry: *badEntry, Rts: 1_700_000_500})
		if applyErr == nil {
			t.Errorf("%s: expected reject (%s), but Apply succeeded", name, vstr(expected, "reason"))
		}
	}
}
