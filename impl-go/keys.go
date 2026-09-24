package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

// AlgorithmIdentifier{1.3.101.112} + BIT STRING header — the fixed 12-byte Ed25519 SPKI prefix.
var spkiPrefix = mustHex("302a300506032b6570032100")

// The 8 canonical small-order Ed25519 public-key encodings (torsion subgroup of order dividing 8).
// Rejected at the key-decode boundary (isStrictPublicKey step 4) — exact mirror of impl-py
// _SMALL_ORDER_PUBKEYS / src/keys.ts SMALL_ORDER_PUBKEYS. A legitimate signing key is never a
// low-order point.
var smallOrderPubkeys = map[string]bool{
	"0100000000000000000000000000000000000000000000000000000000000000": true,
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": true,
	"0000000000000000000000000000000000000000000000000000000000000000": true,
	"0000000000000000000000000000000000000000000000000000000000000080": true,
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05": true,
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85": true,
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a": true,
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa": true,
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// strictB64Decode mirrors impl-py _strict_b64decode and src/keys.ts's canonical round-trip:
// standard base64 only, and the decoded bytes MUST re-encode to exactly the input (rejecting
// embedded whitespace / missing padding / URL-safe / trailing-bit non-canonical forms). This keeps
// sig.value and keyring bytes canonical so both independent verifiers agree byte-for-byte.
func strictB64Decode(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(raw) != s {
		return nil, fmt.Errorf("non-canonical base64")
	}
	return raw, nil
}

// Curve constants for strict public-key validation (RFC 8032 §5.1).
var (
	fieldP  = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	curveD  = mustBig("37095705934669439343138083508754565189542113879843219016388785533085940283555")
	sqrtM1  = mustBig("19681161376707505956807079304988542015446066515923890162744021073123829784752")
	pMinus5 = new(big.Int).Rsh(new(big.Int).Sub(fieldP, big.NewInt(5)), 3) // (p - 5) / 8
)

func mustBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad constant " + s)
	}
	return v
}

// isStrictPublicKey is STRICT PUBLIC-KEY VALIDATION: refuse non-canonical and small-order Ed25519 key
// encodings (RFC 8032 §5.1.3 decoding + small-order rejection). Same rule, same order, as impl-py
// _is_strict_public_key and src/keys.ts isStrictEd25519PublicKeyBytes:
//  1. canonical y (the low 255 bits): y < p;
//  2. y decodes to a curve point: x^2 = (y^2 - 1) / (d*y^2 + 1) has a square root;
//  3. x = 0 with the sign bit set fails (RFC 8032 §5.1.3 step 4);
//  4. not one of the 8 small-order points (canonical encodings; steps 1-3 leave no other spelling).
//
// crypto/ed25519 is not asked: its point decoder accepts non-canonical encodings by design, so the
// rule is enforced here. A key produced by Ed25519 key generation passes every step.
func isStrictPublicKey(raw []byte) bool {
	if len(raw) != 32 {
		return false
	}
	xSign := raw[31]&0x80 != 0
	be := make([]byte, 32)
	for i := 0; i < 32; i++ {
		be[i] = raw[31-i]
	}
	be[0] &= 0x7f
	y := new(big.Int).SetBytes(be)
	if y.Cmp(fieldP) >= 0 {
		return false
	}
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, fieldP)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	u.Mod(u, fieldP)
	v := new(big.Int).Mul(curveD, y2)
	v.Add(v, big.NewInt(1))
	v.Mod(v, fieldP)
	v3 := new(big.Int).Exp(v, big.NewInt(3), fieldP)
	v7 := new(big.Int).Exp(v, big.NewInt(7), fieldP)
	uv7 := new(big.Int).Mul(u, v7)
	uv7.Mod(uv7, fieldP)
	x := new(big.Int).Mul(u, v3)
	x.Mul(x, new(big.Int).Exp(uv7, pMinus5, fieldP))
	x.Mod(x, fieldP)
	vx2 := new(big.Int).Mul(x, x)
	vx2.Mul(vx2, v)
	vx2.Mod(vx2, fieldP)
	if vx2.Cmp(u) != 0 {
		negU := new(big.Int).Neg(u)
		negU.Mod(negU, fieldP)
		if vx2.Cmp(negU) != 0 {
			return false
		}
		x.Mul(x, sqrtM1)
		x.Mod(x, fieldP)
	}
	if x.Sign() == 0 && xSign {
		return false
	}
	return !smallOrderPubkeys[hex.EncodeToString(raw)]
}

// spkiToRaw mirrors impl-py spki_to_raw: strict base64 → 44-byte DER → fixed 12-byte SPKI prefix
// → trailing 32 raw key bytes, with strict public-key validation at key load. Returns exactly 32 bytes.
func spkiToRaw(pubB64 string) ([]byte, error) {
	der, err := strictB64Decode(pubB64)
	if err != nil {
		return nil, err
	}
	if len(der) != 44 || !bytes.Equal(der[:12], spkiPrefix) {
		return nil, fmt.Errorf("not a canonical Ed25519 SPKI")
	}
	raw := der[12:]
	if !isStrictPublicKey(raw) {
		return nil, fmt.Errorf("strict public-key validation: non-canonical or small-order Ed25519 key refused")
	}
	return raw, nil
}

// ed25519Verify verifies a signature against a raw 32-byte public key. Go's crypto/ed25519 (built
// on filippo.io/edwards25519) enforces the canonical scalar S < L (SetCanonicalBytes) and a valid
// point decode, matching impl-py's RFC-8032 reference (S >= L reject + on-curve/canonical checks).
// The pubkey length is guaranteed 32 by spkiToRaw; the guard is a fail-closed safety net so a
// wrong length can never reach ed25519.Verify (which panics on a bad-length public key).
func ed25519Verify(pub32, msg, sig []byte) bool {
	if len(pub32) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub32), msg, sig)
}
