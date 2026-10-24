package membership

import "github.com/squaddle-org/relay/internal/proto"

// RoomID is PROTOCOL.md §3.1: roomId = BLAKE2b-256("SQDL1room" || creatorUserKey || roomNonce).
// A plain hash, not a signature.
func RoomID(creatorUserKey, roomNonce []byte) []byte {
	return proto.Blake2b256([]byte("SQDL1room"), creatorUserKey, roomNonce)
}
