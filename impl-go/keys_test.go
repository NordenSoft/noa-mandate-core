package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// Strict public-key validation: refuse non-canonical and small-order Ed25519 key encodings at key
// load (RFC 8032 §5.1.3 decoding + small-order rejection). Same encodings as the shared corpus
// conformance/vectors/weak-keys/ and the TS / Python unit tests.
var refusedKeyEncodings = map[string]string{
	"small-order: identity":                "0100000000000000000000000000000000000000000000000000000000000000",
	"small-order: order 2":                 "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"small-order: order 4 (even x)":        "0000000000000000000000000000000000000000000000000000000000000000",
	"small-order: order 4 (odd x)":         "0000000000000000000000000000000000000000000000000000000000000080",
	"small-order: order 8 (a)":             "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"small-order: order 8 (b)":             "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"small-order: order 8 (c)":             "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"small-order: order 8 (d)":             "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"x = 0 with sign bit: y = 1":           "0100000000000000000000000000000000000000000000000000000000000080",
	"x = 0 with sign bit: y = p - 1":       "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"non-canonical y: y = p, sign bit set": "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"non-canonical y: y = p + 1":           "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"not a curve point: y = 2":             "0200000000000000000000000000000000000000000000000000000000000000",
}

func spkiB64(raw []byte) string {
	return base64.StdEncoding.EncodeToString(append(append([]byte{}, spkiPrefix...), raw...))
}

func TestStrictPublicKeyRefusesWeakEncodingsAtKeyLoad(t *testing.T) {
	for label, hx := range refusedKeyEncodings {
		raw, err := hex.DecodeString(hx)
		if err != nil {
			t.Fatalf("%s: bad fixture hex", label)
		}
		if isStrictPublicKey(raw) {
			t.Errorf("%s: isStrictPublicKey accepted %s", label, hx)
		}
		if _, err := spkiToRaw(spkiB64(raw)); err == nil {
			t.Errorf("%s: spkiToRaw accepted %s", label, hx)
		}
	}
}

func TestStrictPublicKeyAcceptsGeneratedKeys(t *testing.T) {
	for i := 0; i < 64; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := spkiToRaw(spkiB64(pub)); err != nil {
			t.Fatalf("generated key %x refused: %v", []byte(pub), err)
		}
	}
	// The committed corpus test key (conformance/vectors/keyring.json) must stay accepted.
	if _, err := spkiToRaw("MCowBQYDK2VwAyEAfCMjakcMSx1Azeehv+DU2bchtPTvB+uoloJ0kJNWI24="); err != nil {
		t.Fatalf("corpus test key refused: %v", err)
	}
}
