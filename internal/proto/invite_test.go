package proto

import (
	"bytes"
	"testing"
)

// TestInviteVectors is the Go side of the cross-implementation test for PROTOCOL.md §3.5.
func TestInviteVectors(t *testing.T) {
	for _, v := range loadVectors(t, "invite.json") {
		name := vstr(v, "name")
		input := vobj(v, "input")
		expected := vobj(v, "expected")
		secret := vbytes(t, input, "inviteSecret")
		roomID := vbytes(t, input, "roomId")
		inviteID := vbytes(t, input, "inviteId")

		if accept, ok := vbool(expected, "accept"); ok && !accept {
			envelope := vbytes(t, input, "envelope")
			if _, err := OpenInviteEnvelope(secret, roomID, inviteID, envelope); err == nil {
				t.Errorf("%s: expected reject, but OpenInviteEnvelope succeeded", name)
			}
			continue
		}

		if !bytes.Equal(InviteKey(secret), vbytes(t, expected, "inviteKey")) {
			t.Errorf("%s: inviteKey mismatch", name)
		}

		envelope := vbytes(t, expected, "envelope")
		content, err := OpenInviteEnvelope(secret, roomID, inviteID, envelope)
		if err != nil {
			t.Fatalf("%s: OpenInviteEnvelope: %v", name, err)
		}
		if !bytes.Equal(content.Room, roomID) {
			t.Errorf("%s: room mismatch", name)
		}
		if wantEpoch, ok := input["epoch"].(float64); ok && content.Epoch != uint64(wantEpoch) {
			t.Errorf("%s: epoch = %d, want %d", name, content.Epoch, uint64(wantEpoch))
		}
		if !bytes.Equal(content.EpochKey, vbytes(t, input, "epochKey")) {
			t.Errorf("%s: epochKey mismatch", name)
		}
		if wantName, ok := input["roomName"].(string); ok {
			if !content.HasRoomName || content.RoomName != wantName {
				t.Errorf("%s: roomName = %q (has=%v), want %q", name, content.RoomName, content.HasRoomName, wantName)
			}
		}
	}
}
