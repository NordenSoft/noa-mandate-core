//! Versioned historical verification side API. It authenticates retained receipt signatures and a
//! separately rooted checkpoint without changing the current-use `verify_chain` contract.

use crate::json::Json;
use crate::keys::spki_to_raw;
use crate::schema::is_rfc3339_instant;
use crate::verify::{checkpoint_shape_ok, verify_chain, verify_checkpoint, Status};
use serde_json::{json, Value};
use std::collections::HashMap;

const HISTORICAL_SPEC: &str = "noa.historical-verification/0.1";
const LIFECYCLE_SPEC: &str = "noa.signing-key-lifecycle/0.1";

struct HistoricalTrust {
    keyring: Json,
    retired: HashMap<String, bool>,
    valid_from: HashMap<String, Option<i128>>,
    retired_at: HashMap<String, Option<i128>>,
    lifecycle: bool,
}

fn dimensions(
    integrity: &str,
    completeness: &str,
    attribution: &str,
    retirement: &str,
    witness: &str,
    availability: &str,
) -> Value {
    json!({
        "integrity": integrity,
        "completeness": completeness,
        "attribution": attribution,
        "organizationalIndependence": "UNVERIFIED",
        "evidence": {
            "retirement": retirement,
            "witness": witness,
            "availability": availability
        }
    })
}

fn result(
    classification: &str,
    code: &str,
    dimensions: Value,
    chain: Option<&str>,
    count: usize,
    attributed_through_seq: Option<i64>,
    as_of: Option<&str>,
) -> Value {
    json!({
        "spec": HISTORICAL_SPEC,
        "policy": {"verifierVersion": HISTORICAL_SPEC, "purpose": "historical-audit"},
        "classification": classification,
        "code": code,
        "dimensions": dimensions,
        "chain": chain,
        "count": count,
        "attributedThroughSeq": attributed_through_seq,
        "asOf": as_of
    })
}

fn days_from_civil(mut year: i64, month: i64, day: i64) -> i64 {
    year -= if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 {
        year / 400
    } else {
        (year - 399) / 400
    };
    let yoe = year - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn decimal(bytes: &[u8]) -> Option<i64> {
    let mut out = 0i64;
    for b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        out = out * 10 + i64::from(*b - b'0');
    }
    Some(out)
}

/// UTC nanoseconds. Leap-second checkpoints return None, matching the TypeScript Date.parse gate.
fn parse_instant(value: &str) -> Option<i128> {
    if !is_rfc3339_instant(value) {
        return None;
    }
    let b = value.as_bytes();
    let year = decimal(&b[0..4])?;
    let month = decimal(&b[5..7])?;
    let day = decimal(&b[8..10])?;
    let hour = decimal(&b[11..13])?;
    let minute = decimal(&b[14..16])?;
    let second = decimal(&b[17..19])?;
    if second > 59 {
        return None;
    }
    let mut i = 19usize;
    let mut nanos = 0i128;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let fraction = decimal(&b[start..i])? as i128;
        nanos = fraction * 10i128.pow((9 - (i - start)) as u32);
    }
    let offset_seconds = if b.get(i) == Some(&b'Z') || b.get(i) == Some(&b'z') {
        0i64
    } else {
        let sign = if b.get(i) == Some(&b'+') { 1i64 } else { -1i64 };
        sign * (decimal(&b[i + 1..i + 3])? * 3600 + decimal(&b[i + 4..i + 6])? * 60)
    };
    let seconds = days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second
        - offset_seconds;
    Some(i128::from(seconds) * 1_000_000_000 + nanos)
}

fn parse_keyring(document: &Json) -> Option<HistoricalTrust> {
    let object = document.as_object()?;
    let looks_lifecycle = document.get("spec").and_then(Json::as_str) == Some(LIFECYCLE_SPEC)
        || matches!(document.get("keys"), Some(v) if !matches!(v, Json::Str(_)));
    if !looks_lifecycle {
        let mut flat = Vec::with_capacity(object.len());
        for (kid, public_key) in object {
            let value = public_key.as_str()?;
            if kid.is_empty() || value.is_empty() {
                return None;
            }
            flat.push((kid.clone(), Json::Str(value.to_string())));
        }
        return Some(HistoricalTrust {
            keyring: Json::Object(flat),
            retired: HashMap::new(),
            valid_from: HashMap::new(),
            retired_at: HashMap::new(),
            lifecycle: false,
        });
    }
    if object.len() != 2 || document.get("spec").and_then(Json::as_str) != Some(LIFECYCLE_SPEC) {
        return None;
    }
    let entries = document.get("keys")?.as_object()?;
    if entries.is_empty() {
        return None;
    }
    let mut flat = Vec::with_capacity(entries.len());
    let mut retired = HashMap::new();
    let mut valid_from = HashMap::new();
    let mut retired_at = HashMap::new();
    for (kid, entry) in entries {
        let fields = entry.as_object()?;
        if kid.is_empty()
            || (fields.len() != 2 && fields.len() != 3)
            || entry.get("publicKey").is_none()
            || entry.get("retiredAt").is_none()
            || (fields.len() == 3 && entry.get("validFrom").is_none())
        {
            return None;
        }
        let public_key = entry.get("publicKey")?.as_str()?;
        if public_key.is_empty() {
            return None;
        }
        flat.push((kid.clone(), Json::Str(public_key.to_string())));
        let activation = match entry.get("validFrom") {
            None | Some(Json::Null) => None,
            Some(Json::Str(value)) => Some(parse_instant(value)?),
            _ => return None,
        };
        let retirement = match entry.get("retiredAt")? {
            Json::Null => None,
            Json::Str(value) => {
                let instant = parse_instant(value)?;
                retired.insert(kid.clone(), true);
                Some(instant)
            }
            _ => return None,
        };
        if matches!((activation, retirement), (Some(start), Some(end)) if start >= end) {
            return None;
        }
        valid_from.insert(kid.clone(), activation);
        retired_at.insert(kid.clone(), retirement);
    }
    Some(HistoricalTrust {
        keyring: Json::Object(flat),
        retired,
        valid_from,
        retired_at,
        lifecycle: true,
    })
}

pub fn verify_historical_chain(
    receipts: &Json,
    receipt_root: &Json,
    checkpoint: Option<&Json>,
    checkpoint_root: Option<&Json>,
    identity: Option<&Json>,
) -> Value {
    let witness = if checkpoint.is_some() {
        "PROVIDED"
    } else {
        "NOT_PROVIDED"
    };
    let availability = if checkpoint.is_some() {
        "AVAILABLE"
    } else {
        "NOT_PROVIDED"
    };
    let (arr, count, chain) = match receipts {
        Json::Array(values) => (
            Some(values),
            values.len(),
            values
                .first()
                .and_then(|r| r.get("scope"))
                .and_then(|s| s.get("chain"))
                .and_then(Json::as_str),
        ),
        _ => (None, 0, None),
    };
    let receipt_trust = match parse_keyring(receipt_root) {
        Some(value) => value,
        None => {
            return result(
                "INVALID",
                "RECEIPT_ROOT_INVALID",
                dimensions(
                    "UNANSWERED",
                    "UNANSWERED",
                    "UNATTRIBUTABLE",
                    "NOT_PROVIDED",
                    witness,
                    availability,
                ),
                None,
                0,
                None,
                None,
            )
        }
    };
    let retirement = if receipt_trust.lifecycle {
        "PROVIDED"
    } else {
        "NOT_PROVIDED"
    };

    // CONTROL G2-RETIREMENT-INTEGRITY-RUST: only this historical side API projects retained keys
    // into the unchanged current verifier, and it never forwards a checkpoint through receipt trust.
    let (status, _) = verify_chain(receipts, Some(&receipt_trust.keyring), identity, None);
    if status != Status::Valid {
        return match status {
            Status::Tampered => result(
                "INVALID",
                "RECEIPT_INTEGRITY_FAILURE",
                dimensions(
                    "BROKEN",
                    "UNANSWERED",
                    "UNATTRIBUTABLE",
                    retirement,
                    witness,
                    availability,
                ),
                chain,
                count,
                None,
                None,
            ),
            Status::Untrusted => result(
                "INVALID",
                "RECEIPT_IDENTITY_UNTRUSTED",
                dimensions(
                    "UNANSWERED",
                    "UNANSWERED",
                    "UNATTRIBUTABLE",
                    retirement,
                    witness,
                    availability,
                ),
                chain,
                count,
                None,
                None,
            ),
            _ => result(
                "INVALID",
                "RECEIPT_MALFORMED",
                dimensions(
                    "UNANSWERED",
                    "UNANSWERED",
                    "UNATTRIBUTABLE",
                    retirement,
                    witness,
                    availability,
                ),
                chain,
                count,
                None,
                None,
            ),
        };
    }
    let arr = arr.unwrap();
    let mut by_seq: HashMap<i64, &Json> = HashMap::new();
    for receipt in arr {
        by_seq.insert(
            receipt
                .get("chain")
                .and_then(|c| c.get("seq"))
                .and_then(Json::as_int)
                .unwrap(),
            receipt,
        );
    }
    let head = by_seq.get(&((count - 1) as i64)).unwrap();
    let checkpoint = match checkpoint {
        Some(value) => value,
        None => {
            return result(
                "UNVERIFIED",
                "NO_WITNESS",
                dimensions(
                    "INTACT",
                    "UNANSWERED",
                    "UNATTRIBUTABLE",
                    retirement,
                    "NOT_PROVIDED",
                    "NOT_PROVIDED",
                ),
                chain,
                count,
                None,
                None,
            )
        }
    };
    let checkpoint_root = match checkpoint_root {
        Some(value) => value,
        None => {
            return result(
                "UNVERIFIED",
                "WITNESS_ROOT_NOT_PROVIDED",
                dimensions(
                    "UNANSWERED",
                    "UNANSWERED",
                    "UNATTRIBUTABLE",
                    retirement,
                    "PROVIDED",
                    "AVAILABLE",
                ),
                chain,
                count,
                None,
                None,
            )
        }
    };
    let witness_trust = match parse_keyring(checkpoint_root) {
        Some(value) => value,
        None => {
            return result(
                "UNVERIFIED",
                "WITNESS_ROOT_INVALID",
                dimensions(
                    "UNANSWERED",
                    "UNANSWERED",
                    "UNATTRIBUTABLE",
                    retirement,
                    "PROVIDED",
                    "AVAILABLE",
                ),
                chain,
                count,
                None,
                None,
            )
        }
    };
    if !checkpoint_shape_ok(checkpoint) {
        return result(
            "INVALID",
            "WITNESS_MALFORMED",
            dimensions(
                "BROKEN",
                "UNANSWERED",
                "UNATTRIBUTABLE",
                retirement,
                "PROVIDED",
                "AVAILABLE",
            ),
            chain,
            count,
            None,
            None,
        );
    }
    match verify_checkpoint(checkpoint, Some(&witness_trust.keyring)) {
        "unverified" => {
            return result(
                "UNVERIFIED",
                "WITNESS_KEY_NOT_TRUSTED",
                dimensions(
                    "UNANSWERED",
                    "UNANSWERED",
                    "UNATTRIBUTABLE",
                    retirement,
                    "PROVIDED",
                    "AVAILABLE",
                ),
                chain,
                count,
                None,
                None,
            )
        }
        "ok" => {}
        _ => {
            return result(
                "INVALID",
                "WITNESS_INTEGRITY_FAILURE",
                dimensions(
                    "BROKEN",
                    "UNANSWERED",
                    "UNATTRIBUTABLE",
                    retirement,
                    "PROVIDED",
                    "AVAILABLE",
                ),
                chain,
                count,
                None,
                None,
            )
        }
    }

    let witness_kid = checkpoint
        .get("sig")
        .and_then(|s| s.get("kid"))
        .and_then(Json::as_str)
        .unwrap();
    let witness_public = witness_trust
        .keyring
        .get(witness_kid)
        .and_then(Json::as_str)
        .unwrap();
    let witness_material = match spki_to_raw(witness_public) {
        Ok(value) => value,
        Err(_) => {
            return result(
                "UNVERIFIED",
                "WITNESS_ROOT_INVALID",
                dimensions(
                    "UNANSWERED",
                    "UNANSWERED",
                    "UNATTRIBUTABLE",
                    retirement,
                    "PROVIDED",
                    "AVAILABLE",
                ),
                chain,
                count,
                None,
                None,
            )
        }
    };
    // CONTROL G2-WITNESS-KEY-SEPARATION-RUST: compare canonical decoded SPKI key bytes, not labels.
    for receipt in arr {
        let receipt_kid = receipt
            .get("sig")
            .and_then(|s| s.get("kid"))
            .and_then(Json::as_str)
            .unwrap();
        let receipt_public = receipt_trust
            .keyring
            .get(receipt_kid)
            .and_then(Json::as_str)
            .unwrap();
        if witness_kid == receipt_kid
            || spki_to_raw(receipt_public).ok().as_ref() == Some(&witness_material)
        {
            return result(
                "UNVERIFIED",
                "WITNESS_KEY_NOT_SEPARATE",
                dimensions(
                    "INTACT",
                    "UNANSWERED",
                    "UNATTRIBUTABLE",
                    retirement,
                    "PROVIDED",
                    "AVAILABLE",
                ),
                chain,
                count,
                None,
                None,
            );
        }
    }
    if witness_trust
        .retired
        .get(witness_kid)
        .copied()
        .unwrap_or(false)
    {
        return result(
            "UNVERIFIED",
            "WITNESS_KEY_RETIRED",
            dimensions(
                "INTACT",
                "UNANSWERED",
                "UNATTRIBUTABLE",
                retirement,
                "PROVIDED",
                "AVAILABLE",
            ),
            chain,
            count,
            None,
            None,
        );
    }
    if checkpoint.get("chain").and_then(Json::as_str) != chain {
        return result(
            "CONFLICT",
            "CHECKPOINT_CONFLICT",
            dimensions(
                "INTACT",
                "CONFLICT",
                "UNATTRIBUTABLE",
                retirement,
                "PROVIDED",
                "AVAILABLE",
            ),
            chain,
            count,
            None,
            None,
        );
    }
    let cp_seq = checkpoint.get("highestSeq").and_then(Json::as_int).unwrap();
    let head_seq = head
        .get("chain")
        .and_then(|c| c.get("seq"))
        .and_then(Json::as_int)
        .unwrap();
    if cp_seq > head_seq {
        return result(
            "CONFLICT",
            "CHECKPOINT_AHEAD",
            dimensions(
                "INTACT",
                "CONFLICT",
                "UNATTRIBUTABLE",
                retirement,
                "PROVIDED",
                "MISSING_RELATIVE_TO_CHECKPOINT",
            ),
            chain,
            count,
            None,
            None,
        );
    }
    let checkpointed = by_seq.get(&cp_seq);
    let hash_matches = checkpointed
        .and_then(|r| r.get("chain"))
        .and_then(|c| c.get("hash"))
        .and_then(Json::as_str)
        == checkpoint.get("headHash").and_then(Json::as_str);
    if checkpointed.is_none() || !hash_matches {
        return result(
            "CONFLICT",
            "CHECKPOINT_CONFLICT",
            dimensions(
                "INTACT",
                "CONFLICT",
                "UNATTRIBUTABLE",
                retirement,
                "PROVIDED",
                "AVAILABLE",
            ),
            chain,
            count,
            None,
            None,
        );
    }
    let completeness = if cp_seq == head_seq {
        "HEAD_ANCHORED"
    } else {
        "PREFIX_ANCHORED"
    };
    let checkpoint_time = checkpoint
        .get("ts")
        .and_then(Json::as_str)
        .and_then(parse_instant);
    let mut checkpoint_before_activation =
        if let Some(Some(valid_from)) = witness_trust.valid_from.get(witness_kid) {
            checkpoint_time
                .map(|value| value < *valid_from)
                .unwrap_or(true)
        } else {
            false
        };
    let mut checkpoint_after_retirement = checkpoint_time.is_none();
    for seq in 0..=cp_seq {
        let receipt_kid = by_seq[&seq]
            .get("sig")
            .and_then(|s| s.get("kid"))
            .and_then(Json::as_str)
            .unwrap();
        if let Some(Some(valid_from)) = receipt_trust.valid_from.get(receipt_kid) {
            if checkpoint_time
                .map(|value| value < *valid_from)
                .unwrap_or(true)
            {
                checkpoint_before_activation = true;
            }
        }
        if let Some(Some(retired_at)) = receipt_trust.retired_at.get(receipt_kid) {
            if checkpoint_time
                .map(|value| value >= *retired_at)
                .unwrap_or(true)
            {
                checkpoint_after_retirement = true;
            }
        }
    }
    if checkpoint_before_activation {
        return result(
            "UNVERIFIED",
            "CHECKPOINT_BEFORE_ACTIVATION",
            dimensions(
                "INTACT",
                completeness,
                "UNATTRIBUTABLE",
                retirement,
                "PROVIDED",
                "AVAILABLE",
            ),
            chain,
            count,
            None,
            None,
        );
    }
    if checkpoint_after_retirement {
        return result(
            "UNVERIFIED",
            "CHECKPOINT_AFTER_RETIREMENT",
            dimensions(
                "INTACT",
                completeness,
                "UNATTRIBUTABLE",
                retirement,
                "PROVIDED",
                "AVAILABLE",
            ),
            chain,
            count,
            None,
            None,
        );
    }
    let classification = if completeness == "HEAD_ANCHORED" {
        "VERIFIED"
    } else {
        "PARTIAL"
    };
    let as_of = checkpoint.get("ts").and_then(Json::as_str);
    result(
        classification,
        completeness,
        dimensions(
            "INTACT",
            completeness,
            "ATTRIBUTABLE_AS_OF",
            retirement,
            "PROVIDED",
            "AVAILABLE",
        ),
        chain,
        count,
        Some(cp_seq),
        as_of,
    )
}
