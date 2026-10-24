package proto

import "fmt"

const inviteNonceLength = 24

// InviteEnvelopeContent is PROTOCOL.md §3.5's decrypted envelope body.
type InviteEnvelopeContent struct {
	Room        []byte
	Epoch       uint64
	EpochKey    []byte
	RoomName    string
	HasRoomName bool
}

// InviteKey is `kdf(BLAKE2b(inviteSecret), id=1, ctx="SQDLINVK")` (PROTOCOL.md §3.5).
func InviteKey(inviteSecret []byte) []byte {
	return KdfDeriveFromKey(Blake2b256(inviteSecret), 1, "SQDLINVK", 32)
}

// SealInviteEnvelope builds `nonce || AEAD(inviteKey, nonce, CBOR{0:room,1:epoch,2:epochKey,
// 3:roomName?}, ad=roomId||inviteId)`. The relay itself never calls this (it only stores/serves
// envelopes opaquely, never decrypts or creates them - see package doc) - it exists to pass
// invite.json.
func SealInviteEnvelope(inviteSecret, roomID, inviteID []byte, epoch uint64, epochKey []byte, roomName string, hasRoomName bool, nonce []byte) ([]byte, error) {
	body := map[uint64]any{0: roomID, 1: epoch, 2: epochKey}
	if hasRoomName {
		body[3] = roomName
	}
	plaintext, err := EncodeCanonical(body)
	if err != nil {
		return nil, err
	}
	ad := append(append([]byte{}, roomID...), inviteID...)
	ct, err := AeadEncrypt(InviteKey(inviteSecret), nonce, plaintext, ad)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, nonce...), ct...), nil
}

// OpenInviteEnvelope returns an error (never panics) if envelope doesn't decrypt under
// inviteSecret/roomID/inviteID, or isn't the expected shape.
func OpenInviteEnvelope(inviteSecret, roomID, inviteID, envelope []byte) (*InviteEnvelopeContent, error) {
	if len(envelope) < inviteNonceLength {
		return nil, fmt.Errorf("proto: invite envelope shorter than the nonce")
	}
	nonce := envelope[:inviteNonceLength]
	ct := envelope[inviteNonceLength:]
	ad := append(append([]byte{}, roomID...), inviteID...)
	plaintext, err := AeadDecrypt(InviteKey(inviteSecret), nonce, ct, ad)
	if err != nil {
		return nil, err
	}

	var body map[uint64]any
	if err := DecodeCanonicalInto(plaintext, &body); err != nil {
		return nil, err
	}
	room, _ := body[0].([]byte)
	epoch, _ := body[1].(uint64)
	epochKey, _ := body[2].([]byte)
	roomName, hasRoomName := body[3].(string)
	if room == nil || epochKey == nil {
		return nil, fmt.Errorf("proto: invite envelope missing room or epochKey")
	}
	return &InviteEnvelopeContent{Room: room, Epoch: epoch, EpochKey: epochKey, RoomName: roomName, HasRoomName: hasRoomName}, nil
}
