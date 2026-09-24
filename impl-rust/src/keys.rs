//! Ed25519 verification + SPKI decoding, with the SAME cross-impl strictness the Python/TS references
//! enforce so all three verifiers agree byte-for-byte:
//!   - canonical base64 for `sig.value` and keyring SPKI (decode then require re-encode == input),
//!   - canonical Ed25519 SPKI: exactly 44 DER bytes with the fixed 12-byte prefix → raw 32-byte key,
//!   - strict public-key validation at key load (`is_strict_public_key`): refuse non-canonical and
//!     small-order key encodings (RFC 8032 §5.1.3 decoding + small-order rejection),
//!   - reject a non-canonical signature scalar (S >= L, RFC 8032 §5.1.7 malleability),
//!   - cofactorless verification via ed25519-dalek `verify_strict` (rejects non-canonical / small-order
//!     R and A and uses the strict equation — matching the Python reference's strict equation).
//!
//! Any failure returns `Ok(false)` / `Err` → the caller treats both as TAMPERED, exactly like impl-py.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};

/// DER SPKI prefix for an Ed25519 public key: AlgorithmIdentifier{1.3.101.112} + BIT STRING header.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The 8 canonical small-order Ed25519 public-key encodings (hex of the 32 raw little-endian bytes).
const SMALL_ORDER_PUBKEYS: [&str; 8] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
];

/// q = 2^255 - 19, little-endian bytes.
const Q_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// L = 2^252 + 27742317777372353535851937790883648493, little-endian bytes (Ed25519 group order).
const L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Little-endian `bytes` < little-endian `bound`?
fn le_lt(bytes: &[u8; 32], bound: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if bytes[i] < bound[i] {
            return true;
        }
        if bytes[i] > bound[i] {
            return false;
        }
    }
    false // equal → not strictly less
}

/// Strict CANONICAL base64 decode: reject non-alphabet / bad padding (STANDARD engine) AND non-canonical
/// encodings (decoded bytes must re-encode to exactly the input). Mirrors impl-py `_strict_b64decode`.
pub fn strict_b64decode(s: &str) -> Result<Vec<u8>, String> {
    let raw = STANDARD.decode(s.as_bytes()).map_err(|e| e.to_string())?;
    if STANDARD.encode(&raw) != s {
        return Err("non-canonical base64".into());
    }
    Ok(raw)
}

/// y = 1, little-endian bytes (an x = 0 point: the identity).
const ONE_LE: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// y = q - 1, little-endian bytes (an x = 0 point: the order-2 point).
const Q_MINUS_1_LE: [u8; 32] = [
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// STRICT PUBLIC-KEY VALIDATION: refuse non-canonical and small-order Ed25519 key encodings (RFC 8032
/// §5.1.3 decoding + small-order rejection). Same rule, same order, as impl-py `_is_strict_public_key`
/// and src/keys.ts `isStrictEd25519PublicKeyBytes`:
///   1. canonical y (the low 255 bits): y < q;
///   2. y decodes to a curve point (x^2 = (y^2 - 1) / (d*y^2 + 1) has a square root);
///   3. x = 0 with the sign bit set fails (RFC 8032 §5.1.3 step 4); x = 0 exactly when y = 1 or y = q - 1;
///   4. not one of the 8 small-order points (canonical encodings; steps 1-3 leave no other spelling).
///
/// A key produced by Ed25519 key generation passes every step.
pub(crate) fn is_strict_public_key(raw: &[u8; 32]) -> bool {
    let x_sign = raw[31] & 0x80 != 0;
    let mut y = *raw;
    y[31] &= 0x7f;
    if !le_lt(&y, &Q_LE) {
        return false;
    }
    // Step 2 through the point decoder: with y canonical, decompression succeeds exactly when x exists.
    if VerifyingKey::from_bytes(raw).is_err() {
        return false;
    }
    if x_sign && (y == ONE_LE || y == Q_MINUS_1_LE) {
        return false;
    }
    !SMALL_ORDER_PUBKEYS.contains(&hex_lower(raw).as_str())
}

/// base64(DER SPKI Ed25519) → raw 32-byte key, with strict public-key validation at key load.
pub(crate) fn spki_to_raw(pub_b64: &str) -> Result<[u8; 32], String> {
    let der = strict_b64decode(pub_b64)?;
    if der.len() != 44 || der[..12] != SPKI_PREFIX {
        return Err("not a canonical Ed25519 SPKI".into());
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&der[12..44]);
    if !is_strict_public_key(&raw) {
        return Err(
            "strict public-key validation: non-canonical or small-order Ed25519 key refused".into(),
        );
    }
    Ok(raw)
}

/// Verify an Ed25519 signature (base64 SPKI pubkey, raw message bytes, base64 signature).
/// `Ok(true)` = valid; `Ok(false)` = well-formed but invalid signature; `Err` = encoding/key error.
/// Callers treat every non-`Ok(true)` outcome as TAMPERED (matching impl-py).
pub fn verify_sig(pub_b64: &str, msg: &[u8], sig_b64: &str) -> Result<bool, String> {
    let pub_raw = spki_to_raw(pub_b64)?;
    let sig_bytes = strict_b64decode(sig_b64)?;
    if sig_bytes.len() != 64 {
        return Err("signature is not 64 bytes".into());
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    // S = little-endian sig[32..64]; reject S >= L (malleability / non-canonical scalar).
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig_arr[32..64]);
    if !le_lt(&s, &L_LE) {
        return Ok(false);
    }
    let vk = match VerifyingKey::from_bytes(&pub_raw) {
        Ok(k) => k,
        Err(_) => return Err("public key does not decode to a curve point".into()),
    };
    let sig = Signature::from_bytes(&sig_arr);
    Ok(vk.verify_strict(msg, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strict public-key validation: refuse non-canonical and small-order Ed25519 key encodings at key
    /// load. Same encodings as the shared corpus conformance/vectors/weak-keys/.
    const REFUSED: [(&str, &str); 13] = [
        (
            "small-order: identity",
            "0100000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "small-order: order 2",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ),
        (
            "small-order: order 4 (even x)",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "small-order: order 4 (odd x)",
            "0000000000000000000000000000000000000000000000000000000000000080",
        ),
        (
            "small-order: order 8 (a)",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        ),
        (
            "small-order: order 8 (b)",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        ),
        (
            "small-order: order 8 (c)",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        ),
        (
            "small-order: order 8 (d)",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        ),
        (
            "x = 0 with sign bit: y = 1",
            "0100000000000000000000000000000000000000000000000000000000000080",
        ),
        (
            "x = 0 with sign bit: y = q - 1",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        (
            "non-canonical y: y = q, sign bit set",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        (
            "non-canonical y: y = q + 1",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ),
        (
            "not a curve point: y = 2",
            "0200000000000000000000000000000000000000000000000000000000000000",
        ),
    ];

    fn raw_of(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    fn spki_b64(raw: &[u8; 32]) -> String {
        let mut der = SPKI_PREFIX.to_vec();
        der.extend_from_slice(raw);
        STANDARD.encode(der)
    }

    #[test]
    fn strict_public_key_refuses_weak_encodings_at_key_load() {
        for (label, hex) in REFUSED {
            let raw = raw_of(hex);
            assert!(
                !is_strict_public_key(&raw),
                "{label}: is_strict_public_key accepted {hex}"
            );
            assert!(
                spki_to_raw(&spki_b64(&raw)).is_err(),
                "{label}: spki_to_raw accepted {hex}"
            );
        }
    }

    #[test]
    fn strict_public_key_accepts_the_corpus_test_key() {
        // conformance/vectors/keyring.json — a real generated key must stay accepted.
        assert!(
            spki_to_raw("MCowBQYDK2VwAyEAfCMjakcMSx1Azeehv+DU2bchtPTvB+uoloJ0kJNWI24=").is_ok()
        );
    }
}
