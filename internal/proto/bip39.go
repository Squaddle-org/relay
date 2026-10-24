package proto

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"strings"
)

//go:embed wordlist_english.txt
var englishWordlistRaw string

var englishWordlist = strings.Fields(englishWordlistRaw)

var englishWordIndex = func() map[string]int {
	m := make(map[string]int, len(englishWordlist))
	for i, w := range englishWordlist {
		m[w] = i
	}
	return m
}()

var validWordCounts = map[int]bool{12: true, 15: true, 18: true, 21: true, 24: true}
var validEntropyLengths = map[int]bool{16: true, 20: true, 24: true, 28: true, 32: true}

// EntropyToMnemonic is BIP39 (PROTOCOL.md §2.1) - SHA-256 is BIP39's own checksum requirement,
// not a Squaddle protocol primitive (everything Squaddle signs/hashes still uses BLAKE2b-256).
func EntropyToMnemonic(entropy []byte) ([]string, error) {
	if !validEntropyLengths[len(entropy)] {
		return nil, fmt.Errorf("proto: entropy must be 16/20/24/28/32 bytes, was %d", len(entropy))
	}
	checksumBitCount := len(entropy) / 4
	checksum := sha256.Sum256(entropy)
	bits := bytesToBits(entropy) + bytesToBits(checksum[:])[:checksumBitCount]

	words := make([]string, 0, len(bits)/11)
	for i := 0; i < len(bits); i += 11 {
		words = append(words, englishWordlist[bitsToInt(bits[i:i+11])])
	}
	return words, nil
}

// MnemonicToEntropy is the reverse of EntropyToMnemonic, rejecting a wrong word count, an unknown
// word, or a checksum mismatch.
func MnemonicToEntropy(words []string) ([]byte, error) {
	if !validWordCounts[len(words)] {
		return nil, fmt.Errorf("proto: word count must be one of [12 15 18 21 24], was %d", len(words))
	}
	var bits strings.Builder
	for _, w := range words {
		idx, ok := englishWordIndex[w]
		if !ok {
			return nil, fmt.Errorf("proto: %q is not a BIP39 English wordlist word", w)
		}
		bits.WriteString(intToBits(idx, 11))
	}
	bitString := bits.String()
	totalBits := len(words) * 11
	entropyBitCount := totalBits * 32 / 33
	checksumBitCount := totalBits - entropyBitCount

	entropy := bitsToBytes(bitString[:entropyBitCount])
	expectedChecksumBits := bitString[entropyBitCount:]
	checksum := sha256.Sum256(entropy)
	actualChecksumBits := bytesToBits(checksum[:])[:checksumBitCount]
	if expectedChecksumBits != actualChecksumBits {
		return nil, fmt.Errorf("proto: checksum mismatch")
	}
	return entropy, nil
}

func bytesToBits(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) * 8)
	for _, by := range b {
		sb.WriteString(intToBits(int(by), 8))
	}
	return sb.String()
}

func intToBits(n, width int) string {
	buf := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		if n&1 == 1 {
			buf[i] = '1'
		} else {
			buf[i] = '0'
		}
		n >>= 1
	}
	return string(buf)
}

func bitsToInt(bits string) int {
	n := 0
	for _, c := range bits {
		n <<= 1
		if c == '1' {
			n |= 1
		}
	}
	return n
}

func bitsToBytes(bits string) []byte {
	out := make([]byte, len(bits)/8)
	for i := range out {
		out[i] = byte(bitsToInt(bits[i*8 : i*8+8]))
	}
	return out
}
