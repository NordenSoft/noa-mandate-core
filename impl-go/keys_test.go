package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"
)

// Strict public-key validation: refuse non-canonical and small-order Ed25519 key encodings at key
// load (RFC 8032 §5.1.3 decoding + small-order rejection). Same encodings as the shared corpus
// conformance/vectors/strict-ed25519/ and src/keys.ts's unit tests.
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

// mixedOrder returns a genuine key plus the order-2 point: (x, y) -> (-x, -y). Same curve, mixed order.
func mixedOrder(pub []byte) []byte {
	be := make([]byte, 32)
	for i := 0; i < 32; i++ {
		be[i] = pub[31-i]
	}
	be[0] &= 0x7f
	y := new(big.Int).SetBytes(be)
	negY := new(big.Int).Sub(fieldP, y).FillBytes(make([]byte, 32))
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		out[i] = negY[31-i]
	}
	out[31] = (out[31] & 0x7f) | ((pub[31] & 0x80) ^ 0x80)
	return out
}

func TestStrictPublicKeyRefusesMixedOrderKeys(t *testing.T) {
	for i := 0; i < 16; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		mixed := mixedOrder(pub)
		if _, _, ok := strictDecode(mixed); !ok {
			t.Fatalf("mixed-order key %x must still decode (it is a curve point)", mixed)
		}
		if isStrictPublicKey(mixed) {
			t.Fatalf("mixed-order key %x accepted", mixed)
		}
	}
}

func TestStrictSignatureRRefusesNonCanonicalAndSmallOrderR(t *testing.T) {
	for label, hx := range refusedKeyEncodings {
		raw, _ := hex.DecodeString(hx)
		if isStrictSignatureR(raw) {
			t.Errorf("%s: isStrictSignatureR accepted %s", label, hx)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("strict R")
	sig := ed25519.Sign(priv, msg)
	if !isStrictSignatureR(sig[:32]) || !ed25519Verify(pub, msg, sig) {
		t.Fatal("a genuine signature must pass the R rule and verify")
	}
}

// ── Test-only key-holder arithmetic for the signature-R rule (S = r + k*a with the private scalar).

func scalarMul(s *big.Int, p [4]*big.Int) [4]*big.Int {
	acc := [4]*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)}
	for i := s.BitLen() - 1; i >= 0; i-- {
		acc = extendedAdd(acc, acc)
		if s.Bit(i) == 1 {
			acc = extendedAdd(acc, p)
		}
	}
	return acc
}

func encodeExtended(p [4]*big.Int) []byte {
	zi := new(big.Int).ModInverse(p[2], fieldP)
	x := new(big.Int).Mod(new(big.Int).Mul(p[0], zi), fieldP)
	y := new(big.Int).Mod(new(big.Int).Mul(p[1], zi), fieldP)
	be := y.FillBytes(make([]byte, 32))
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		out[i] = be[31-i]
	}
	if x.Bit(0) == 1 {
		out[31] |= 0x80
	}
	return out
}

func extendedOf(enc string) [4]*big.Int {
	raw, _ := hex.DecodeString(enc)
	x, y, ok := strictDecode(raw)
	if !ok {
		panic("bad test point " + enc)
	}
	return [4]*big.Int{x, y, big.NewInt(1), new(big.Int).Mod(new(big.Int).Mul(x, y), fieldP)}
}

func leInt(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[i] = b[len(b)-1-i]
	}
	return new(big.Int).SetBytes(be)
}

func signWithR(a *big.Int, pub, msg, rBytes []byte, r *big.Int) []byte {
	h := sha512.New()
	h.Write(rBytes)
	h.Write(pub)
	h.Write(msg)
	k := new(big.Int).Mod(leInt(h.Sum(nil)), groupL)
	s := new(big.Int).Mod(new(big.Int).Add(r, new(big.Int).Mul(k, a)), groupL)
	sBe := s.FillBytes(make([]byte, 32))
	sig := append([]byte{}, rBytes...)
	for i := 0; i < 32; i++ {
		sig = append(sig, sBe[31-i])
	}
	return sig
}

// Knockout proof (signature-R rule): key-holder signatures made at test time with a fresh key.
func TestKnockoutProofSignatureRRule(t *testing.T) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] = (h[31] & 127) | 64
	a := leInt(h[:32])
	base := extendedOf("5866666666666666666666666666666666666666666666666666666666666666")
	if !bytes.Equal(encodeExtended(scalarMul(a, base)), pub) {
		t.Fatal("test key derivation does not match crypto/ed25519")
	}
	rh := sha512.Sum512(append(append([]byte{}, seed...), 'r'))
	r := new(big.Int).Mod(leInt(rh[:]), groupL)
	msg := []byte("signature-R rule")

	control := signWithR(a, pub, msg, encodeExtended(scalarMul(r, base)), r)
	if !ed25519Verify(pub, msg, control) {
		t.Fatal("the control signature must verify")
	}
	identity, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	identitySigned, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000080")
	mixedR := encodeExtended(extendedAdd(scalarMul(r, base), extendedOf("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")))
	cases := map[string][]byte{
		"R = identity":                           signWithR(a, pub, msg, identity, big.NewInt(0)),
		"R = identity spelled with the sign bit": signWithR(a, pub, msg, identitySigned, big.NewInt(0)),
		"R = rB + small-order point":             signWithR(a, pub, msg, mixedR, r),
	}
	for label, sig := range cases {
		if ed25519Verify(pub, msg, sig) {
			t.Errorf("%s: accepted", label)
		}
	}
}
