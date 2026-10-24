package proto

import (
	"encoding/binary"
	"math/bits"
)

// golang.org/x/crypto/blake2b only exposes New(size, key) - no salt/personalization - so it
// cannot implement crypto_kdf_derive_from_key (PROTOCOL.md §1: BLAKE2b keyed by the master key,
// salted with the subkey id, personalized with the 8-char context; see libsodium's
// kdf_blake2b.c). The compression function below (blake2bIV, blake2bPrecomputed, blake2bCompress)
// is adapted from golang.org/x/crypto/blake2b/blake2b_generic.go (BSD-3-Clause,
// Copyright 2016 The Go Authors) - only the initialization (KdfDeriveFromKey) differs, to set the
// salt/person words the upstream package never sets.
//
// KdfDeriveFromKey only ever needs to hash a *single* block (libsodium's construction calls the
// compression primitive with an empty message, so the 32-byte key is the sole block, and it is
// always the final block) - this is why there's no general multi-block streaming logic here.
var blake2bIV = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

var blake2bPrecomputed = [12][16]byte{
	{0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15},
	{14, 4, 9, 13, 10, 8, 15, 6, 1, 0, 11, 5, 12, 2, 7, 3},
	{11, 12, 5, 15, 8, 0, 2, 13, 10, 3, 7, 9, 14, 6, 1, 4},
	{7, 3, 13, 11, 9, 1, 12, 14, 2, 5, 4, 15, 6, 10, 0, 8},
	{9, 5, 2, 10, 0, 7, 4, 15, 14, 11, 6, 3, 1, 12, 8, 13},
	{2, 6, 0, 8, 12, 10, 11, 3, 4, 7, 15, 1, 13, 5, 14, 9},
	{12, 1, 14, 4, 5, 15, 13, 10, 0, 6, 9, 8, 7, 3, 2, 11},
	{13, 7, 12, 3, 11, 14, 1, 9, 5, 15, 8, 2, 0, 4, 6, 10},
	{6, 14, 11, 0, 15, 9, 3, 8, 12, 13, 1, 10, 2, 7, 4, 5},
	{10, 8, 7, 1, 2, 4, 6, 5, 15, 9, 3, 13, 11, 14, 12, 0},
	{0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15},
	{14, 4, 9, 13, 10, 8, 15, 6, 1, 0, 11, 5, 12, 2, 7, 3},
}

// blake2bCompress processes exactly one 128-byte block with counter c and finalization flag
// (0 for an interior block, all-ones for the final block), matching RFC 7693 §3.2.
func blake2bCompress(h *[8]uint64, c *[2]uint64, flag uint64, block []byte) {
	var m [16]uint64
	for i := range m {
		m[i] = binary.LittleEndian.Uint64(block[i*8:])
	}

	c0, c1 := c[0]+128, c[1]
	if c0 < 128 {
		c1++
	}

	v0, v1, v2, v3, v4, v5, v6, v7 := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
	v8, v9, v10, v11, v12, v13, v14, v15 := blake2bIV[0], blake2bIV[1], blake2bIV[2], blake2bIV[3], blake2bIV[4], blake2bIV[5], blake2bIV[6], blake2bIV[7]
	v12 ^= c0
	v13 ^= c1
	v14 ^= flag

	for _, s := range blake2bPrecomputed {
		v0 += m[s[0]]
		v0 += v4
		v12 ^= v0
		v12 = bits.RotateLeft64(v12, -32)
		v8 += v12
		v4 ^= v8
		v4 = bits.RotateLeft64(v4, -24)
		v1 += m[s[1]]
		v1 += v5
		v13 ^= v1
		v13 = bits.RotateLeft64(v13, -32)
		v9 += v13
		v5 ^= v9
		v5 = bits.RotateLeft64(v5, -24)
		v2 += m[s[2]]
		v2 += v6
		v14 ^= v2
		v14 = bits.RotateLeft64(v14, -32)
		v10 += v14
		v6 ^= v10
		v6 = bits.RotateLeft64(v6, -24)
		v3 += m[s[3]]
		v3 += v7
		v15 ^= v3
		v15 = bits.RotateLeft64(v15, -32)
		v11 += v15
		v7 ^= v11
		v7 = bits.RotateLeft64(v7, -24)

		v0 += m[s[4]]
		v0 += v4
		v12 ^= v0
		v12 = bits.RotateLeft64(v12, -16)
		v8 += v12
		v4 ^= v8
		v4 = bits.RotateLeft64(v4, -63)
		v1 += m[s[5]]
		v1 += v5
		v13 ^= v1
		v13 = bits.RotateLeft64(v13, -16)
		v9 += v13
		v5 ^= v9
		v5 = bits.RotateLeft64(v5, -63)
		v2 += m[s[6]]
		v2 += v6
		v14 ^= v2
		v14 = bits.RotateLeft64(v14, -16)
		v10 += v14
		v6 ^= v10
		v6 = bits.RotateLeft64(v6, -63)
		v3 += m[s[7]]
		v3 += v7
		v15 ^= v3
		v15 = bits.RotateLeft64(v15, -16)
		v11 += v15
		v7 ^= v11
		v7 = bits.RotateLeft64(v7, -63)

		v0 += m[s[8]]
		v0 += v5
		v15 ^= v0
		v15 = bits.RotateLeft64(v15, -32)
		v10 += v15
		v5 ^= v10
		v5 = bits.RotateLeft64(v5, -24)
		v1 += m[s[9]]
		v1 += v6
		v12 ^= v1
		v12 = bits.RotateLeft64(v12, -32)
		v11 += v12
		v6 ^= v11
		v6 = bits.RotateLeft64(v6, -24)
		v2 += m[s[10]]
		v2 += v7
		v13 ^= v2
		v13 = bits.RotateLeft64(v13, -32)
		v8 += v13
		v7 ^= v8
		v7 = bits.RotateLeft64(v7, -24)
		v3 += m[s[11]]
		v3 += v4
		v14 ^= v3
		v14 = bits.RotateLeft64(v14, -32)
		v9 += v14
		v4 ^= v9
		v4 = bits.RotateLeft64(v4, -24)

		v0 += m[s[12]]
		v0 += v5
		v15 ^= v0
		v15 = bits.RotateLeft64(v15, -16)
		v10 += v15
		v5 ^= v10
		v5 = bits.RotateLeft64(v5, -63)
		v1 += m[s[13]]
		v1 += v6
		v12 ^= v1
		v12 = bits.RotateLeft64(v12, -16)
		v11 += v12
		v6 ^= v11
		v6 = bits.RotateLeft64(v6, -63)
		v2 += m[s[14]]
		v2 += v7
		v13 ^= v2
		v13 = bits.RotateLeft64(v13, -16)
		v8 += v13
		v7 ^= v8
		v7 = bits.RotateLeft64(v7, -63)
		v3 += m[s[15]]
		v3 += v4
		v14 ^= v3
		v14 = bits.RotateLeft64(v14, -16)
		v9 += v14
		v4 ^= v9
		v4 = bits.RotateLeft64(v4, -63)
	}

	h[0] ^= v0 ^ v8
	h[1] ^= v1 ^ v9
	h[2] ^= v2 ^ v10
	h[3] ^= v3 ^ v11
	h[4] ^= v4 ^ v12
	h[5] ^= v5 ^ v13
	h[6] ^= v6 ^ v14
	h[7] ^= v7 ^ v15

	c[0], c[1] = c0, c1
}

// KdfDeriveFromKey is crypto_kdf_derive_from_key for the "blake2b" primitive (the only one
// PROTOCOL.md uses): BLAKE2b keyed by master (32 bytes), salted with id (8-byte little-endian,
// zero-padded to 16), personalized with context (exactly 8 ASCII chars, zero-padded to 16),
// hashing an empty message. outLen must be 1..64.
func KdfDeriveFromKey(master []byte, id uint64, context string, outLen int) []byte {
	if len(master) != 32 {
		panic("proto: kdf master key must be 32 bytes")
	}
	if len(context) != 8 {
		panic("proto: kdf context must be exactly 8 ASCII chars")
	}
	if outLen < 1 || outLen > 64 {
		panic("proto: kdf outLen must be 1..64")
	}

	h := blake2bIV
	h[0] ^= uint64(outLen) | uint64(len(master))<<8 | (1 << 16) | (1 << 24)

	var salt [16]byte
	binary.LittleEndian.PutUint64(salt[0:8], id)
	h[4] ^= binary.LittleEndian.Uint64(salt[0:8])
	h[5] ^= binary.LittleEndian.Uint64(salt[8:16])

	var person [16]byte
	copy(person[:], context)
	h[6] ^= binary.LittleEndian.Uint64(person[0:8])
	h[7] ^= binary.LittleEndian.Uint64(person[8:16])

	var block [128]byte
	copy(block[:], master)

	c := [2]uint64{0, 0}
	blake2bCompress(&h, &c, ^uint64(0), block[:])

	out := make([]byte, outLen)
	for i := 0; i < (outLen+7)/8; i++ {
		var word [8]byte
		binary.LittleEndian.PutUint64(word[:], h[i])
		copy(out[i*8:], word[:]) // copy truncates on the last, possibly-partial word
	}
	return out
}
