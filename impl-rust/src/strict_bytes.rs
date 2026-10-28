//! The opt-in strict-bytes verifier profile. `native` (the default) verifies parsed values and never
//! judges the received encoding. `strict-bytes` additionally requires the ORIGINAL bytes of a bare
//! chain file to equal UTF8(canonicalize(parsed array)) — the complete array in presented order,
//! brackets and separators included — before any receipt check. Nothing is trimmed, BOM-stripped,
//! translated or repaired first. A mismatch is MALFORMED with a detail starting NON_CANONICAL_BYTES;
//! equality hands the same parsed tree to the unchanged `verify_chain`, so a canonical input gets the
//! native verdict.

use crate::jcs::canonicalize;
use crate::json::{self, Json};
use crate::verify::{verify_chain, Status};

pub const PROFILE_NATIVE: &str = "native";
pub const PROFILE_STRICT_BYTES: &str = "strict-bytes";
pub const NON_CANONICAL_BYTES: &str = "NON_CANONICAL_BYTES";

pub fn valid_profile(p: &str) -> bool {
    p == PROFILE_NATIVE || p == PROFILE_STRICT_BYTES
}

/// Strict UTF-8 decode (`str::from_utf8`, which keeps a BOM as U+FEFF so the strict parser refuses
/// it), strict parse and, under strict-bytes, one whole-input comparison. `Err` carries the MALFORMED
/// detail of a refusal.
pub fn admit_chain_bytes(data: &[u8], profile: &str) -> Result<Json, String> {
    if !valid_profile(profile) {
        return Err("profile must be native or strict-bytes".into());
    }
    let text = std::str::from_utf8(data).map_err(|_| "input is not valid UTF-8".to_string())?;
    let value = json::parse(text)?;
    if profile == PROFILE_STRICT_BYTES && canonicalize(&value).as_bytes() != data {
        return Err(format!(
            "{NON_CANONICAL_BYTES}: receipts: the input bytes are not the UTF-8 JCS serialization of the parsed chain"
        ));
    }
    Ok(value)
}

/// Byte-entry wrapper of `verify_chain`: the same verdicts, plus the opt-in strict-bytes gate above.
/// The trust inputs are parsed values exactly as `verify_chain` takes them; their rules are unchanged.
#[cfg_attr(not(test), allow(dead_code))]
pub fn verify_chain_bytes(
    data: &[u8],
    keyring: Option<&Json>,
    identity: Option<&Json>,
    checkpoint: Option<&Json>,
    warnings: Option<&mut Vec<String>>,
    profile: &str,
) -> (Status, String) {
    match admit_chain_bytes(data, profile) {
        Ok(receipts) => verify_chain(&receipts, keyring, identity, checkpoint, warnings),
        Err(detail) => (Status::Malformed, detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = "../conformance/vectors/strict-bytes";

    fn read(name: &str) -> Vec<u8> {
        std::fs::read(format!("{DIR}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    /// Every case of the shared corpus through the byte-entry API, against the manifest's AUTHORED
    /// expectations (scripts/gen-vectors.ts section 12).
    #[test]
    fn manifest_cases_through_verify_chain_bytes() {
        let manifest: serde_json::Value = serde_json::from_slice(&read("manifest.json")).expect("manifest");
        let cases = manifest["cases"].as_array().expect("cases");
        assert_eq!(cases.len(), 13, "the 13 authored cases");
        let keyring_text = String::from_utf8(read(manifest["keyring"].as_str().expect("keyring"))).expect("keyring utf-8");
        let keyring = json::parse(&keyring_text).expect("keyring parse");
        for c in cases {
            let name = c["name"].as_str().expect("name");
            let data = read(c["file"].as_str().expect("file"));
            let (status, detail) = verify_chain_bytes(&data, Some(&keyring), None, None, None, PROFILE_STRICT_BYTES);
            assert_eq!(status.label(), c["strict"]["status"].as_str().expect("strict status"), "{name} strict: {detail}");
            if let Some(disc) = c["strict"]["discriminator"].as_str() {
                assert!(detail.starts_with(disc), "{name} strict detail {detail:?} must start with {disc}");
            }
            if let Some(native) = c["native"]["status"].as_str() {
                let (n_status, n_detail) = verify_chain_bytes(&data, Some(&keyring), None, None, None, PROFILE_NATIVE);
                assert_eq!(n_status.label(), native, "{name} native: {n_detail}");
            }
        }
        let (s, _) = verify_chain_bytes(b"[]", None, None, None, None, "strict");
        assert_eq!(s.label(), "MALFORMED", "an unknown profile is MALFORMED");
    }

    /// The shared authored JCS input through this port's own parser and canonicalizer.
    #[test]
    fn jcs_literal_bytes() {
        let input = String::from_utf8(read("jcs-literal-input.json")).expect("input utf-8");
        let value = json::parse(&input).expect("parse");
        assert_eq!(canonicalize(&value).as_bytes(), read("jcs-literal-expected.json").as_slice());
    }
}
