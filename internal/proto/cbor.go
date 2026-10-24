package proto

import (
	"bytes"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// canonicalDecMode is permissive about shortest-form ints and map-key order (fxamacker/cbor
// doesn't enforce those on decode) but does reject indefinite length and duplicate map keys.
// DecodeCanonical closes the remaining gap by re-encoding and comparing bytes - see its doc.
var canonicalDecMode = mustDecMode()

// canonicalEncMode is RFC 8949 §4.2.1 ("Core Deterministic Encoding"): shortest-form ints,
// definite lengths, map keys sorted by encoded bytes - exactly CanonicalCborCodec's contract.
var canonicalEncMode = mustEncMode()

func mustDecMode() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}

func mustEncMode() cbor.EncMode {
	m, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return m
}

// DecodeCanonical decodes data and returns an error unless data is *the* unique canonical
// encoding of its value (PROTOCOL.md §1: "A decoder MUST reject ..."). fxamacker/cbor's
// DecOptions reject indefinite length and duplicate map keys directly; non-shortest-form ints
// and out-of-order map keys are caught here by re-encoding the decoded value with
// CoreDetEncOptions and comparing bytes to the input - any mismatch means the input was not
// already canonical.
func DecodeCanonical(data []byte) (any, error) {
	var v any
	if err := canonicalDecMode.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("proto: not well-formed CBOR: %w", err)
	}
	reencoded, err := canonicalEncMode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("proto: cannot re-encode decoded value: %w", err)
	}
	if !bytes.Equal(reencoded, data) {
		return nil, fmt.Errorf("proto: not canonical CBOR (non-shortest-form int/length or out-of-order map key)")
	}
	return v, nil
}

// DecodeCanonicalInto is DecodeCanonical plus a convenience typed unmarshal (e.g. into a struct
// using "keyasint" tags) once canonicality is confirmed.
func DecodeCanonicalInto(data []byte, v any) error {
	if _, err := DecodeCanonical(data); err != nil {
		return err
	}
	return canonicalDecMode.Unmarshal(data, v)
}

// EncodeCanonical encodes v as canonical CBOR (RFC 8949 §4.2.1).
func EncodeCanonical(v any) ([]byte, error) {
	return canonicalEncMode.Marshal(v)
}
