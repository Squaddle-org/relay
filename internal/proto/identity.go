package proto

// UserIdentity is PROTOCOL.md §2.1's seed -> user-keys derivation chain. The relay never derives
// this on its own behalf (it's a pure client/onboarding concern) - it exists to cross-check
// identity.json against core's (Kotlin) and spec/tools's (Python) independent implementations.
type UserIdentity struct {
	Entropy    []byte
	UserKey    []byte
	UserBoxKey []byte
	BackupKey  []byte
}

// DeriveUserIdentity requires 32-byte entropy (PROTOCOL.md §2.1).
func DeriveUserIdentity(entropy []byte) UserIdentity {
	if len(entropy) != 32 {
		panic("proto: entropy must be 32 bytes")
	}
	master := Blake2b256(entropy)
	userSignSeed := KdfDeriveFromKey(master, 1, "SQDLUSIG", 32)
	userBoxSeed := KdfDeriveFromKey(master, 2, "SQDLUBOX", 32)
	backupKey := KdfDeriveFromKey(master, 3, "SQDLBKUP", 32)
	return UserIdentity{
		Entropy:    entropy,
		UserKey:    Ed25519SeedKeypairPublic(userSignSeed),
		UserBoxKey: X25519SeedKeypairPublic(userBoxSeed),
		BackupKey:  backupKey,
	}
}
