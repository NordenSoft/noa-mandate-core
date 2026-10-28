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
    let value = if profile == PROFILE_STRICT_BYTES {
        json::parse(&negative_zero_as_zero(text))?
    } else {
        json::parse(text)?
    };
    if profile == PROFILE_STRICT_BYTES && canonicalize(&value).as_bytes() != data {
        return Err(format!(
            "{NON_CANONICAL_BYTES}: receipts: the input bytes are not the UTF-8 JCS serialization of the parsed chain"
        ));
    }
    Ok(value)
}

/// STRICT PRE-PARSE ONLY. serde_json hands the lexical integer `-0` to the visitor as the float `-0.0`,
/// which `json.rs` refuses as a float; the TS, Python, Go and C# parsers admit it as integer zero and
/// the strict-bytes comparison then refuses it as NON_CANONICAL_BYTES. For that parity this copy reads
/// a `-0` number token (outside strings, not followed by a digit, `.`, `e` or `E`) as `0`. It is used
/// for the PARSE only: the comparison above reads the original `data`, where the `-0` remains, and
/// `canonicalize` never emits `-0`, so an input that contained one is always refused. `-0.0`, `-0e0`
/// and `-01` are left untouched and keep their existing parse errors; native parsing is not affected.
fn negative_zero_as_zero(text: &str) -> std::borrow::Cow<'_, str> {
    let b = text.as_bytes();
    let mut out: Option<Vec<u8>> = None;
    let mut in_string = false;
    let mut escaped = false;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
        } else if c == b'"' {
            in_string = true;
        } else if c == b'-'
            && b.get(i + 1) == Some(&b'0')
            && !matches!(b.get(i + 2), Some(b'0'..=b'9' | b'.' | b'e' | b'E'))
        {
            // Every byte here is ASCII structure, so dropping the '-' keeps the text valid UTF-8.
            out.get_or_insert_with(|| b[..i].to_vec());
            i += 1;
            continue;
        }
        if let Some(o) = out.as_mut() {
            o.push(c);
        }
        i += 1;
    }
    match out {
        // Removing an ASCII byte keeps valid UTF-8; the fallback (the original text, which then fails
        // its float parse as MALFORMED) only keeps this function panic-free.
        Some(o) => String::from_utf8(o)
            .map(std::borrow::Cow::Owned)
            .unwrap_or(std::borrow::Cow::Borrowed(text)),
        None => std::borrow::Cow::Borrowed(text),
    }
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
        let manifest: serde_json::Value =
            serde_json::from_slice(&read("manifest.json")).expect("manifest");
        let cases = manifest["cases"].as_array().expect("cases");
        assert_eq!(cases.len(), 14, "the 14 authored cases");
        let keyring_text = String::from_utf8(read(manifest["keyring"].as_str().expect("keyring")))
            .expect("keyring utf-8");
        let keyring = json::parse(&keyring_text).expect("keyring parse");
        for c in cases {
            let name = c["name"].as_str().expect("name");
            let data = read(c["file"].as_str().expect("file"));
            let (status, detail) = verify_chain_bytes(
                &data,
                Some(&keyring),
                None,
                None,
                None,
                PROFILE_STRICT_BYTES,
            );
            assert_eq!(
                status.label(),
                c["strict"]["status"].as_str().expect("strict status"),
                "{name} strict: {detail}"
            );
            if let Some(disc) = c["strict"]["discriminator"].as_str() {
                assert!(
                    detail.starts_with(disc),
                    "{name} strict detail {detail:?} must start with {disc}"
                );
            }
            if let Some(native) = c["native"]["status"].as_str() {
                let (n_status, n_detail) =
                    verify_chain_bytes(&data, Some(&keyring), None, None, None, PROFILE_NATIVE);
                assert_eq!(n_status.label(), native, "{name} native: {n_detail}");
            }
        }
        let (s, _) = verify_chain_bytes(b"[]", None, None, None, None, "strict");
        assert_eq!(s.label(), "MALFORMED", "an unknown profile is MALFORMED");
    }

    /// `-0` handling: only the strict pre-parse reads the integer token `-0` as `0`; strings, floats and
    /// native parsing are untouched (Codex Astra QA, the Rust `-0` divergence).
    #[test]
    fn negative_zero_strict_pre_parse_only() {
        assert_eq!(
            negative_zero_as_zero(r#"[-0,"-0",-0.0,-0e1,-01,{"a":-0}]"#),
            r#"[0,"-0",-0.0,-0e1,-01,{"a":0}]"#
        );
        assert_eq!(negative_zero_as_zero(r#"["a\"-0",-0]"#), r#"["a\"-0",0]"#);
        let (s, d) = verify_chain_bytes(
            &read("negative-zero.json"),
            None,
            None,
            None,
            None,
            PROFILE_STRICT_BYTES,
        );
        assert_eq!(s.label(), "MALFORMED");
        assert!(d.starts_with(NON_CANONICAL_BYTES), "strict -0 detail {d:?}");
        assert!(
            admit_chain_bytes(b"[-0]", PROFILE_NATIVE).is_err(),
            "native -0 handling is unchanged"
        );
    }

    /// The shared authored JCS input through this port's own parser and canonicalizer.
    #[test]
    fn jcs_literal_bytes() {
        let input = String::from_utf8(read("jcs-literal-input.json")).expect("input utf-8");
        let value = json::parse(&input).expect("parse");
        assert_eq!(
            canonicalize(&value).as_bytes(),
            read("jcs-literal-expected.json").as_slice()
        );
    }
}
