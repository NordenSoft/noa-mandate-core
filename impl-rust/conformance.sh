#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Conformance runner for the Rust NOA-receipt verifier (impl-rust) vs the Python
# reference (impl-py/noa_verify.py). GROUND TRUTH = impl-py exit code.
#
# For every receipt vector it runs BOTH verifiers with IDENTICAL arguments and asserts the exit codes
# match. One mismatch fails the whole run (no partial credit — a single silently-accepted attack is a
# complete failure). Non-receipt fixtures (trust inputs / docs) are excluded explicitly, with the reason.
#
# Exit: 0 = every checked vector agreed with impl-py; 1 = at least one mismatch.
# ─────────────────────────────────────────────────────────────────────────────
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"          # worktree root: holds conformance/ + impl-py/
BIN="$SCRIPT_DIR/target/release/noa-verify"
PY="${PYTHON:-python3}"
PYV="$ROOT/impl-py/noa_verify.py"
CONF="$ROOT/conformance"
G="$CONF/golden/0.3.0"
V="$CONF/vectors"

if [[ ! -x "$BIN" ]]; then
  echo "FATAL: $BIN not built. Run: (cd $SCRIPT_DIR && cargo build --release)"; exit 2
fi

# The Rust unit suite (schema.rs cross-field coherence + the calendar layer, one boundary at a time)
# runs HERE, in the one script CI actually invokes for this implementation — otherwise `cargo test`
# is a test nobody runs. Skipped only when cargo is genuinely absent, and SAID OUT LOUD when skipped:
# a silently-skipped suite reads exactly like a passing one.
if command -v cargo >/dev/null 2>&1; then
  ( cd "$SCRIPT_DIR" && cargo test --quiet ) || { echo "FATAL: rust unit tests FAILED"; exit 1; }
else
  echo "NOTE: cargo not on PATH — the Rust UNIT suite was NOT run (the vector comparison below still is)"
fi

PASS=0; FAIL=0
declare -a FAILED=()
WARN_SEEN=0 # warning-parity cases on which impl-py printed at least one timestamp-order warning
DUP_SEEN=0  # warning-parity cases on which impl-py printed at least one duplicate-id warning

# run_case <category> <label> <arg...>
# runs impl-py and the rust bin with the same args; compares exit codes.
run_case() {
  local cat="$1"; local label="$2"; shift 2
  # EXISTENCE GATE (2026-08-15). A missing vector file made BOTH verifiers exit 3, the codes
  # "agreed", and the case counted as PASS — so deleting a vector silently deleted its guarantee.
  # A file that is not there proves nothing about two implementations agreeing.
  local __arg
  for __arg in "$@"; do
    [[ "$__arg" == --* ]] && continue
    if [[ ! -f "$__arg" ]]; then
      TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
      printf '  FAIL  MISSING VECTOR FILE: %s  (%s)\n' "$__arg" "$label"
      return
    fi
  done
  "$PY" "$PYV" "$@" >/dev/null 2>&1; local pe=$?
  "$BIN" "$@" >/dev/null 2>&1; local re=$?
  local names=( VALID UNVERIFIED TAMPERED MALFORMED USAGE UNTRUSTED )
  # map exit 5 -> index 5 (UNTRUSTED); exits 0..4 map directly
  local pn="${names[$pe]:-EXIT$pe}"; local rn="${names[$re]:-EXIT$re}"
  if [[ "$pe" == "$re" ]]; then
    PASS=$((PASS+1))
    printf '  PASS  [%-13s] %-52s py=%s(%d) rust=%s(%d)\n' "$cat" "$label" "$pn" "$pe" "$rn" "$re"
  else
    FAIL=$((FAIL+1)); FAILED+=("$label")
    printf '  FAIL  [%-13s] %-52s py=%s(%d) rust=%s(%d)\n' "$cat" "$label" "$pn" "$pe" "$rn" "$re"
  fi
}

# WARNING PARITY (scripts/gen-vectors.ts 10c, 10d and 10e, spec §5 and §2). run_case compares exit codes
# only, so it cannot see a missing or different warning. For each ts-order/, independent-fields/ and
# duplicate-id/ chain both verifiers must exit with the same code AND print the same stable warnings
# ("ts-backwards: seq N" / "ts-not-comparable: seq N" / "duplicate-id: seq N"), in the same order;
# impl-py/conformance.mjs pins impl-py's exit
# code and expected list. conformance/warning-parity.py reads each JSON result with a JSON parser: a
# "warnings" member that is not an array of strings, or a code anywhere else in the result, fails the
# case on either side. These lines start with "WARN-" on purpose: warning parity is not a verdict class
# and scripts/conformance-matrix.mjs counts only PASS/FAIL verdict lines. A mismatch still fails this run.
WARN_PARITY="$CONF/warning-parity.py"
WARN_REF=""
WARN_PORT=""

# warn_agree <reference output> <port output>: 0 only when conformance/warning-parity.py reads both
# results as the documented shape and they carry the same codes in the same order. Leaves each side's
# reading (the codes as a JSON array, or "INVALID: <reason>") in WARN_REF and WARN_PORT for the report.
warn_agree() {
  local rv pv
  WARN_REF="$("$PY" "$WARN_PARITY" codes "$1" 2>&1)"; rv=$?
  WARN_PORT="$("$PY" "$WARN_PARITY" codes "$2" 2>&1)"; pv=$?
  [[ "$rv" -eq 0 && "$pv" -eq 0 && "$WARN_REF" == "$WARN_PORT" ]]
}

# GATE SELF-TEST, run before the cases: the decision above must be able to fail. The helper's own table
# of wrong shapes must read as expected, two identical correct results must agree, and a result carrying
# the code as a bare string in place of the "warnings" array must not agree with a correct one.
warn_selftest() {
  local good='{"status":"VALID","warnings":["ts-backwards: seq 1"]}'
  local bad='{"status":"VALID","warnings":"ts-backwards: seq 1"}'
  local out
  if ! out="$("$PY" "$WARN_PARITY" --selftest 2>&1)"; then
    printf '%s\n' "$out"
    FAIL=$((FAIL+1)); FAILED+=("warning-parity self-test: conformance/warning-parity.py --selftest failed")
    printf '  WARN-FAIL  self-test: conformance/warning-parity.py --selftest failed\n'
  elif ! warn_agree "$good" "$good"; then
    FAIL=$((FAIL+1)); FAILED+=("warning-parity self-test: two identical correct results did not agree")
    printf '  WARN-FAIL  self-test: two identical correct results did not agree [%s] [%s]\n' "$WARN_REF" "$WARN_PORT"
  elif warn_agree "$good" "$bad"; then
    FAIL=$((FAIL+1)); FAILED+=("warning-parity self-test: a string in place of the warnings array was accepted")
    printf '  WARN-FAIL  self-test: a string in place of the warnings array was accepted [%s]\n' "$WARN_PORT"
  else
    PASS=$((PASS+1))
    printf '  WARN-PASS  self-test: a string in place of the warnings array fails the comparison [%s]\n' "$WARN_PORT"
  fi
}

# run_warn_case <label> <chain file> <arg...>; the category column is the chain file's folder.
run_warn_case() {
  local label="$1"; shift
  local __arg pyout rsout pe re agree cat
  cat="$(basename "$(dirname "$1")")"
  for __arg in "$@"; do
    [[ "$__arg" == --* ]] && continue
    if [[ ! -f "$__arg" ]]; then
      FAIL=$((FAIL+1)); FAILED+=("$label (missing vector file)")
      printf '  WARN-FAIL  MISSING VECTOR FILE: %s  (%s)\n' "$__arg" "$label"
      return
    fi
  done
  pyout="$("$PY" "$PYV" "$@" 2>/dev/null)"; pe=$?
  rsout="$("$BIN" "$@" 2>/dev/null)"; re=$?
  warn_agree "$pyout" "$rsout"; agree=$?
  [[ "$WARN_REF" == '["'* ]] && WARN_SEEN=$((WARN_SEEN+1))
  [[ "$WARN_REF" == *'"duplicate-id: seq '* ]] && DUP_SEEN=$((DUP_SEEN+1))
  if [[ "$pe" == "$re" && "$agree" -eq 0 ]]; then
    PASS=$((PASS+1))
    printf '  WARN-PASS  [%-13s] %-52s py=%d rust=%d  %s\n' "$cat" "$label" "$pe" "$re" "$WARN_REF"
  else
    FAIL=$((FAIL+1)); FAILED+=("$label (warnings py=$WARN_REF rust=$WARN_PORT)")
    printf '  WARN-FAIL  [%-13s] %-52s py=%d %s rust=%d %s\n' "$cat" "$label" "$pe" "$WARN_REF" "$re" "$WARN_PORT"
  fi
}

echo "════════════════════════════════════════════════════════════════════════"
echo " NOA-receipt conformance: impl-rust  vs  impl-py (ground truth)"
echo " rust: $BIN"
echo " py  : $PY $PYV"
echo "════════════════════════════════════════════════════════════════════════"

echo
echo "── GOLDEN v0.3.0 backcompat (MANIFEST scenarios, static file combos) ──"
run_case golden      "genesis + keyring (VALID)"                 "$G/genesis/chain.json" "$G/genesis/keyring.json"
run_case golden      "genesis, no keyring (UNVERIFIED)"          "$G/genesis/chain.json"
run_case golden      "multi + keyring (VALID)"                   "$G/multi/chain.json" "$G/multi/keyring.json"
run_case golden      "multi, no keyring (UNVERIFIED)"            "$G/multi/chain.json"
run_case golden      "multi + keyring + checkpoint (VALID)"      "$G/multi/chain.json" "$G/multi/keyring.json" --checkpoint "$G/multi/checkpoint.json"
run_case golden      "identity + keyring + manifest (VALID)"     "$G/identity/chain.json" "$G/identity/keyring.json" --identity "$G/identity/manifest.json"
run_case golden      "identity + keyring, no manifest (VALID)"   "$G/identity/chain.json" "$G/identity/keyring.json"
run_case golden      "impersonation, no manifest (VALID kid-lvl)" "$G/identity/impersonation-chain.json" "$G/identity/keyring.json"
run_case golden      "impersonation + manifest (UNTRUSTED)"      "$G/identity/impersonation-chain.json" "$G/identity/keyring.json" --identity "$G/identity/manifest.json"

echo
echo "── ATTACK vectors (keyring = vectors/keyring.json; checkpoint where relevant) ──"
KR="$V/keyring.json"
run_case attack      "tampered-content"                          "$V/attack/tampered-content.json" "$KR"
run_case attack      "wrong-signature"                           "$V/attack/wrong-signature.json" "$KR"
run_case attack      "unknown-kid"                               "$V/attack/unknown-kid.json" "$KR"
run_case attack      "key-swap"                                  "$V/attack/key-swap.json" "$KR"
run_case attack      "key-swap-resigned"                         "$V/attack/key-swap-resigned.json" "$KR"
run_case attack      "seq-gap"                                   "$V/attack/seq-gap.json" "$KR"
run_case attack      "head-truncated"                            "$V/attack/head-truncated.json" "$KR"
run_case attack      "dup-seq"                                   "$V/attack/dup-seq.json" "$KR"
run_case attack      "cross-chain-splice"                        "$V/attack/cross-chain-splice.json" "$KR"
# Cross-tenant splice laundered through an OPTIONAL-field omission, and the two legitimate
# absent<->present transitions that must STAY valid (see scripts/gen-vectors.ts 5d).
run_case attack      "tenant-splice-via-absent"                  "$V/attack/tenant-splice-via-absent.json" "$KR"
run_case attack      "tenant-splice-via-absent-long"             "$V/attack/tenant-splice-via-absent-long.json" "$KR"
run_case valid       "tenant-omission-then-same-tenant"          "$V/tenant-omission-then-same-tenant.json" "$KR"
run_case valid       "tenant-enrichment-absent-first"            "$V/tenant-enrichment-absent-first.json" "$KR"
# CROSS-FIELD COHERENCE (2026-08-14): cryptographically PERFECT receipts whose SIGNED BODY
# contradicts itself — VALID in all five verifiers before these rules landed. MALFORMED, decided
# with no key material. The three `valid` companions pin the other half: a rule that refuses every
# receipt is an outage, and the leap second (23:59:60) is a real instant.
run_case attack      "coherence-sandbox-principal"               "$V/attack/coherence-sandbox-principal.json" "$KR"
run_case attack      "coherence-simulated-not-sandboxed"         "$V/attack/coherence-simulated-not-sandboxed.json" "$KR"
run_case attack      "coherence-irreversible-with-rollbackref"   "$V/attack/coherence-irreversible-with-rollbackref.json" "$KR"
run_case attack      "coherence-rolled-back-irreversible"        "$V/attack/coherence-rolled-back-irreversible.json" "$KR"
run_case attack      "coherence-ts-not-an-instant"               "$V/attack/coherence-ts-not-an-instant.json" "$KR"
run_case valid       "coherence-consistent-sandbox"              "$V/coherence-consistent-sandbox.json" "$KR"
run_case valid       "coherence-rolled-back-consistent"          "$V/coherence-rolled-back-consistent.json" "$KR"
run_case valid       "ts-leap-second (23:59:60 is a real instant)" "$V/ts-leap-second.json" "$KR"
run_case attack      "relinked"                                  "$V/attack/relinked.json" "$KR"
run_case attack      "forged-genesis"                            "$V/attack/forged-genesis.json" "$KR"
run_case attack      "tail-truncated (+ checkpoint)"             "$V/attack/tail-truncated.json" "$KR" --checkpoint "$V/checkpoint.json"
run_case attack      "forged-checkpoint (+ forged cp)"           "$V/attack/forged-checkpoint-chain.json" "$KR" --checkpoint "$V/attack/forged-checkpoint-cp.json"
run_case attack      "forged-checkpoint-cp as receipts (MALF)"   "$V/attack/forged-checkpoint-cp.json" "$KR"

echo
echo "── STRICT-ED25519 vectors (refused at key load / non-canonical S → TAMPERED) ──"
# STRICT Ed25519 KEY AND SCALAR VALIDATION (scripts/gen-vectors.ts 11). Each keyring maps the corpus kid to a
# public key that strict public-key validation refuses at key load (non-canonical or small-order encoding,
# RFC 8032 §5.1.3 decoding + small-order rejection); the chain is genuine, so every case must be TAMPERED.
SE="$V/strict-ed25519"
run_case strict-key  "strict-ed25519/low-order pubkey #0 (identity)"  "$V/valid-chain.json" "$SE/keyring-low-order-0.json"
run_case strict-key  "strict-ed25519/low-order pubkey #1 (order 2)"  "$V/valid-chain.json" "$SE/keyring-low-order-1.json"
run_case strict-key  "strict-ed25519/low-order pubkey #2 (order 4)"  "$V/valid-chain.json" "$SE/keyring-low-order-2.json"
run_case strict-key  "strict-ed25519/low-order pubkey #3 (order 4)"  "$V/valid-chain.json" "$SE/keyring-low-order-3.json"
run_case strict-key  "strict-ed25519/low-order pubkey #4 (order 8)"  "$V/valid-chain.json" "$SE/keyring-low-order-4.json"
run_case strict-key  "strict-ed25519/low-order pubkey #5 (order 8)"  "$V/valid-chain.json" "$SE/keyring-low-order-5.json"
run_case strict-key  "strict-ed25519/low-order pubkey #6 (order 8)"  "$V/valid-chain.json" "$SE/keyring-low-order-6.json"
run_case strict-key  "strict-ed25519/low-order pubkey #7 (order 8)"  "$V/valid-chain.json" "$SE/keyring-low-order-7.json"
run_case strict-key  "strict-ed25519/x0-sign y=1 non-canonical pubkey"  "$V/valid-chain.json" "$SE/keyring-x0-sign-y-1.json"
run_case strict-key  "strict-ed25519/x0-sign y=p-1 non-canonical pubkey"  "$V/valid-chain.json" "$SE/keyring-x0-sign-y-p-minus-1.json"
run_case strict-key  "strict-ed25519/y=p non-canonical pubkey"  "$V/valid-chain.json" "$SE/keyring-y-p-sign.json"
run_case strict-key  "strict-ed25519/y=p+1 non-canonical pubkey"  "$V/valid-chain.json" "$SE/keyring-y-p-plus-1.json"
run_case strict-key  "strict-ed25519/off-curve pubkey y=2"  "$V/valid-chain.json" "$SE/keyring-off-curve-y-2.json"
run_case strict-key  "strict-ed25519/mixed-order pubkey"  "$V/valid-chain.json" "$SE/keyring-mixed-order.json"
run_case strict-key  "strict-ed25519/s-not-canonical malleability + kr"  "$SE/chain-s-not-canonical.json" "$KR"

echo
echo "── TS-ORDER vectors (warning parity; every chain stays VALID) ──"
warn_selftest
TO="$V/ts-order"
run_warn_case "backwards-one-second + kr"                "$TO/backwards-one-second.json" "$KR"
run_warn_case "backwards-one-nanosecond + kr"            "$TO/backwards-one-nanosecond.json" "$KR"
run_warn_case "backwards-after-offset + kr"              "$TO/backwards-after-offset.json" "$KR"
run_warn_case "equal-instant + kr"                       "$TO/equal-instant.json" "$KR"
run_warn_case "second-60-ordered + kr"                   "$TO/second-60-ordered.json" "$KR"
run_warn_case "not-comparable-second-60 + kr"            "$TO/not-comparable-second-60.json" "$KR"
run_warn_case "backwards-one-second, no keyring"         "$TO/backwards-one-second.json"
run_warn_case "second-60-then-next-minute + kr"          "$TO/second-60-then-next-minute.json" "$KR"
run_warn_case "not-comparable-second-60-equal + kr"      "$TO/not-comparable-second-60-equal.json" "$KR"
run_warn_case "not-comparable-real-leap-second + kr"     "$TO/not-comparable-real-leap-second.json" "$KR"
run_warn_case "year-boundary-positive-offset + kr"       "$TO/year-boundary-positive-offset.json" "$KR"
run_warn_case "month-boundary-negative-offset + kr"      "$TO/month-boundary-negative-offset.json" "$KR"
run_warn_case "leap-day-positive-offset + kr"            "$TO/leap-day-positive-offset.json" "$KR"
# Two warnings in one run, in seq order; the shuffled file stores the same receipts in the array order
# seq 1, seq 2, seq 0, and verifiers order by chain.seq, so both must print the same two codes.
run_warn_case "backwards-twice + kr"                     "$TO/backwards-twice.json" "$KR"
run_warn_case "backwards-twice-shuffled + kr"            "$TO/backwards-twice-shuffled.json" "$KR"
# ANTI-VACUITY: if the extraction matched nothing anywhere, every case above would "agree" on an
# empty list. Eleven of those cases must carry an impl-py warning, so zero is a broken runner.
if [[ "$WARN_SEEN" -eq 0 ]]; then
  FAIL=$((FAIL+1)); FAILED+=("ts-order warning parity is vacuous (no impl-py warning seen)")
  printf '  WARN-FAIL  vacuous: impl-py printed no timestamp-order warning on any ts-order case\n'
fi

echo
echo "── INDEPENDENT-FIELDS vectors (accepted as written; exit-code and warning parity) ──"
# Spec §2 "Independent fields" (scripts/gen-vectors.ts 10d): field combinations this version deliberately
# does not couple. impl-py/conformance.mjs pins impl-py at VALID with no timestamp-order warning; parity
# holds impl-rust to the same. WARN- lines, like the ts-order cases, so the verdict matrix is unchanged.
IND="$V/independent-fields"
run_warn_case "risk-class-vs-reversible + kr"            "$IND/risk-class-vs-reversible.json" "$KR"
run_warn_case "mode-vs-verdict-and-approval + kr"        "$IND/mode-vs-verdict-and-approval.json" "$KR"
run_warn_case "compliance-deny-vs-executed + kr"         "$IND/compliance-deny-vs-executed.json" "$KR"
run_warn_case "approval-at-after-ts + kr"                "$IND/approval-at-after-ts.json" "$KR"

echo
echo "── DUPLICATE-ID vectors (warning parity; every chain stays VALID) ──"
# Spec §5 step 6c (scripts/gen-vectors.ts 10e): every receipt whose id equals the id of a lower seq is
# reported as "duplicate-id: seq N", in seq order and after that seq's timestamp-order code; ids are exact
# strings after JSON parsing. impl-py/conformance.mjs pins impl-py's exit code and expected list.
DUP="$V/duplicate-id"
run_warn_case "pair + kr"                                "$DUP/pair.json" "$KR"
run_warn_case "pair, no keyring"                         "$DUP/pair.json"
# The shuffled file stores the same receipts in the array order seq 1, seq 3, seq 0, seq 2; verifiers
# order by chain.seq, so both must print "duplicate-id: seq 2" then "duplicate-id: seq 3".
run_warn_case "three-holders + kr"                       "$DUP/three-holders.json" "$KR"
run_warn_case "three-holders-shuffled + kr"              "$DUP/three-holders-shuffled.json" "$KR"
run_warn_case "case-differs + kr"                        "$DUP/case-differs.json" "$KR"
run_warn_case "nfc-vs-nfd + kr"                          "$DUP/nfc-vs-nfd.json" "$KR"
run_warn_case "with-ts-backwards + kr"                   "$DUP/with-ts-backwards.json" "$KR"
run_warn_case "escaped-spelling + kr"                    "$DUP/escaped-spelling.json" "$KR"
# ANTI-VACUITY: six of those cases must carry an impl-py duplicate-id warning, so none seen is a broken
# runner (the ts-order cases never carry one).
if [[ "$DUP_SEEN" -eq 0 ]]; then
  FAIL=$((FAIL+1)); FAILED+=("duplicate-id warning parity is vacuous (no impl-py duplicate-id warning seen)")
  printf '  WARN-FAIL  vacuous: impl-py printed no duplicate-id warning on any duplicate-id case\n'
fi

echo
echo "── MALFORMED vectors (strict parse / structural → MALFORMED) ──"
for f in "$V"/malformed/*.json; do
  run_case malformed  "$(basename "$f")"                         "$f" "$KR"
done

echo
echo "── VALID top-level vector ──"
run_case valid       "valid-chain + keyring (VALID)"             "$V/valid-chain.json" "$KR"
run_case valid       "valid-chain, no keyring (UNVERIFIED)"      "$V/valid-chain.json"

echo
echo "── EXHAUSTIVE FILE SWEEP: every *.json under conformance/{golden,vectors} run"
echo "   identically (bare, no keyring) on BOTH — nothing silently skipped ──"
SWEEP_PASS=0; SWEEP_FAIL=0
while IFS= read -r f; do
  "$PY" "$PYV" "$f" >/dev/null 2>&1; pe=$?
  "$BIN" "$f" >/dev/null 2>&1; re=$?
  if [[ "$pe" == "$re" ]]; then
    SWEEP_PASS=$((SWEEP_PASS+1))
  else
    SWEEP_FAIL=$((SWEEP_FAIL+1)); FAILED+=("sweep:$f (py=$pe rust=$re)")
    printf '  SWEEP-FAIL  %-60s py=%d rust=%d\n' "${f#$ROOT/}" "$pe" "$re"
  fi
done < <(find "$G" "$V" -type f -name '*.json' | sort)
printf '  sweep: %d/%d files agreed (bare receipts path)\n' "$SWEEP_PASS" $((SWEEP_PASS+SWEEP_FAIL))

echo
echo "── EXCLUDED non-receipt fixtures (not receipt chains; run only as trust inputs) ──"
cat <<'EOF'
  conformance/golden/0.3.0/MANIFEST.json        — golden manifest (documentation/oracle), not a chain
  conformance/golden/0.3.0/README.md            — docs
  conformance/golden/0.3.0/*/keyring.json       — trust root (kid -> SPKI), consumed as [keyring.json]
  conformance/golden/0.3.0/identity/manifest.json — identity manifest, consumed via --identity
  conformance/golden/0.3.0/multi/checkpoint.json  — signed checkpoint, consumed via --checkpoint
  conformance/vectors/keyring.json              — trust root, consumed as [keyring.json]
  conformance/vectors/checkpoint.json           — signed checkpoint, consumed via --checkpoint
  conformance/vectors/attack/forged-checkpoint-cp.json — attacker checkpoint, consumed via --checkpoint
  conformance/vectors/strict-ed25519/keyring-*.json — trust roots holding refused keys, consumed as [keyring.json]
  (each is nonetheless swept above as a bare receipts arg → both verifiers agree at MALFORMED)
  NOTE: the golden "multi-truncated dropLast" MANIFEST scenario is a DYNAMIC transform (no static file),
        so its static analogue here is the attack/tail-truncated vector (+ checkpoint) above.
EOF

echo
echo "════════════════════════════════════════════════════════════════════════"
TOTAL=$((PASS+FAIL))
echo " CURATED CASES : $PASS/$TOTAL matched impl-py"
echo " SWEEP         : $SWEEP_PASS/$((SWEEP_PASS+SWEEP_FAIL)) matched impl-py"
if [[ "$FAIL" -eq 0 && "$SWEEP_FAIL" -eq 0 ]]; then
  echo " RESULT        : PASS (all receipt-vectors verdict-identical to impl-py)"
  echo "════════════════════════════════════════════════════════════════════════"
  exit 0
else
  echo " RESULT        : FAIL"
  for x in "${FAILED[@]}"; do echo "   - $x"; done
  echo "════════════════════════════════════════════════════════════════════════"
  exit 1
fi
