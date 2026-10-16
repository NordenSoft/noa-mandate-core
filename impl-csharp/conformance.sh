#!/usr/bin/env bash
#
# Cross-implementation conformance: the C# verifier (impl-csharp) vs the Python reference
# (impl-py/noa_verify.py, GROUND TRUTH). For every receipt vector under conformance/golden/0.3.0,
# conformance/vectors, and conformance/vectors/attack, BOTH verifiers run with identical arguments
# and their EXIT CODES must match. impl-py is authoritative; a mismatch fails the whole run.
#
# Exit-code legend: 0 VALID · 1 UNVERIFIED · 2 TAMPERED · 3 MALFORMED · 4 USAGE · 5 UNTRUSTED
#
# Usage:  impl-csharp/conformance.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO"

PY="impl-py/noa_verify.py"
EXE="$SCRIPT_DIR/bin/Release/net10.0/noa-verify.dll"

# Build once (quiet) if the binary is missing.
if [ ! -f "$EXE" ]; then
  echo "building impl-csharp (Release)..."
  dotnet build -c Release "$SCRIPT_DIR" >/dev/null || { echo "BUILD FAILED"; exit 2; }
fi

# KEY-LOAD SELF-CHECK. The vector comparison below proves verdict agreement with impl-py; it cannot
# show WHERE a key was refused (a TAMPERED verdict looks the same whether the key or the signature
# failed). This program compiles the same src/Crypto.cs and calls its key-load and signature-R
# functions directly on conformance/vectors/strict-ed25519/. A failure fails the whole run.
echo "== key-load self-check (impl-csharp/selfcheck) =="
dotnet run --project "$SCRIPT_DIR/selfcheck/selfcheck.csproj" -c Release -- conformance/vectors \
  || { echo "KEY-LOAD SELF-CHECK FAILED"; exit 1; }

TOTAL=0; PASS=0; FAIL=0
WARN_SEEN=0 # warning-parity cases on which impl-py printed at least one timestamp-order warning

run_case() {
  label="$1"; shift
  # EXISTENCE GATE (2026-08-15). A missing vector file made BOTH verifiers exit 3, the codes
  # "agreed", and the case counted as PASS — so deleting a vector silently deleted its guarantee.
  # Observed live: the leap-second pin evaporated while the runner printed TOTAL=48 PASS=48 FAIL=0.
  # A file that is not there proves nothing about two implementations agreeing.
  for __arg in "$@"; do
    case "$__arg" in
      --*) continue ;;
    esac
    if [ ! -f "$__arg" ]; then
      TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
      printf '  FAIL  MISSING VECTOR FILE: %s  (%s)\n' "$__arg" "$label"
      return
    fi
  done
  python3 "$PY" "$@" >/dev/null 2>&1; py_code=$?
  dotnet "$EXE" "$@" >/dev/null 2>&1; cs_code=$?
  TOTAL=$((TOTAL+1))
  if [ "$py_code" = "$cs_code" ]; then
    PASS=$((PASS+1))
    printf '  PASS  py=%s cs=%s  %s\n' "$py_code" "$cs_code" "$label"
  else
    FAIL=$((FAIL+1))
    printf '  FAIL  py=%s cs=%s  %s\n' "$py_code" "$cs_code" "$label"
  fi
}

# WARNING PARITY (scripts/gen-vectors.ts 10c and 10d, spec §5 and §2). run_case compares exit codes only,
# so it cannot see a missing or different warning. For each ts-order/ and independent-fields/ chain both
# verifiers must exit with the same code AND print the same timestamp-order warnings ("ts-backwards:
# seq N" / "ts-not-comparable: seq N"), in the same order; impl-py/conformance.mjs pins impl-py's exit
# code and expected list. conformance/warning-parity.py reads each JSON result with a JSON parser: a
# "warnings" member that is not an array of strings, or a code anywhere else in the result, fails the
# case on either side. These lines start with "WARN-" on purpose: warning parity is not a verdict class
# and scripts/conformance-matrix.mjs counts only PASS/FAIL verdict lines. A mismatch still fails this run.
WARN_PARITY="conformance/warning-parity.py"
WARN_REF=""
WARN_PORT=""

# warn_agree <reference output> <port output>: 0 only when conformance/warning-parity.py reads both
# results as the documented shape and they carry the same codes in the same order. Leaves each side's
# reading (the codes as a JSON array, or "INVALID: <reason>") in WARN_REF and WARN_PORT for the report.
warn_agree() {
  local rv pv
  WARN_REF="$(python3 "$WARN_PARITY" codes "$1" 2>&1)"; rv=$?
  WARN_PORT="$(python3 "$WARN_PARITY" codes "$2" 2>&1)"; pv=$?
  [ "$rv" -eq 0 ] && [ "$pv" -eq 0 ] && [ "$WARN_REF" = "$WARN_PORT" ]
}

# GATE SELF-TEST, run before the cases: the decision above must be able to fail. The helper's own table
# of wrong shapes must read as expected, two identical correct results must agree, and a result carrying
# the code as a bare string in place of the "warnings" array must not agree with a correct one.
warn_selftest() {
  local good='{"status":"VALID","warnings":["ts-backwards: seq 1"]}'
  local bad='{"status":"VALID","warnings":"ts-backwards: seq 1"}'
  local out
  TOTAL=$((TOTAL+1))
  if ! out="$(python3 "$WARN_PARITY" --selftest 2>&1)"; then
    printf '%s\n' "$out"
    FAIL=$((FAIL+1)); printf '  WARN-FAIL  self-test: conformance/warning-parity.py --selftest failed\n'
  elif ! warn_agree "$good" "$good"; then
    FAIL=$((FAIL+1)); printf '  WARN-FAIL  self-test: two identical correct results did not agree [%s] [%s]\n' "$WARN_REF" "$WARN_PORT"
  elif warn_agree "$good" "$bad"; then
    FAIL=$((FAIL+1)); printf '  WARN-FAIL  self-test: a string in place of the warnings array was accepted [%s]\n' "$WARN_PORT"
  else
    PASS=$((PASS+1)); printf '  WARN-PASS  self-test: a string in place of the warnings array fails the comparison [%s]\n' "$WARN_PORT"
  fi
}

run_warn_case() {
  local label="$1"; shift
  local __arg py_out cs_out py_code cs_code agree
  for __arg in "$@"; do
    case "$__arg" in
      --*) continue ;;
    esac
    if [ ! -f "$__arg" ]; then
      TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
      printf '  WARN-FAIL  MISSING VECTOR FILE: %s  (%s)\n' "$__arg" "$label"
      return
    fi
  done
  py_out="$(python3 "$PY" "$@" 2>/dev/null)"; py_code=$?
  cs_out="$(dotnet "$EXE" "$@" 2>/dev/null)"; cs_code=$?
  warn_agree "$py_out" "$cs_out"; agree=$?
  case "$WARN_REF" in '["'*) WARN_SEEN=$((WARN_SEEN+1)) ;; esac
  TOTAL=$((TOTAL+1))
  if [ "$py_code" = "$cs_code" ] && [ "$agree" -eq 0 ]; then
    PASS=$((PASS+1))
    printf '  WARN-PASS  py=%s cs=%s  %s  %s\n' "$py_code" "$cs_code" "$WARN_REF" "$label"
  else
    FAIL=$((FAIL+1))
    printf '  WARN-FAIL  py=%s %s  cs=%s %s  %s\n' "$py_code" "$WARN_REF" "$cs_code" "$WARN_PORT" "$label"
  fi
}

KR="conformance/vectors/keyring.json"
CP="conformance/vectors/checkpoint.json"
GEN="conformance/golden/0.3.0"

echo "== golden/0.3.0 (frozen v0.3.0-signed artifacts) =="
run_case "golden genesis + keyring (VALID)"                     "$GEN/genesis/chain.json" "$GEN/genesis/keyring.json"
run_case "golden genesis no-keyring (UNVERIFIED)"              "$GEN/genesis/chain.json"
run_case "golden multi + keyring (VALID)"                      "$GEN/multi/chain.json" "$GEN/multi/keyring.json"
run_case "golden multi no-keyring (UNVERIFIED)"               "$GEN/multi/chain.json"
run_case "golden multi + keyring + checkpoint (VALID)"        "$GEN/multi/chain.json" "$GEN/multi/keyring.json" --checkpoint "$GEN/multi/checkpoint.json"
run_case "golden identity + keyring (VALID kid-level)"        "$GEN/identity/chain.json" "$GEN/identity/keyring.json"
run_case "golden identity + keyring + manifest (VALID)"       "$GEN/identity/chain.json" "$GEN/identity/keyring.json" --identity "$GEN/identity/manifest.json"
run_case "golden impersonation + keyring (VALID kid-level)"   "$GEN/identity/impersonation-chain.json" "$GEN/identity/keyring.json"
run_case "golden impersonation + keyring + manifest (UNTRUSTED)" "$GEN/identity/impersonation-chain.json" "$GEN/identity/keyring.json" --identity "$GEN/identity/manifest.json"

echo "== conformance/vectors (happy path) =="
run_case "vectors valid-chain + keyring (VALID)"              "conformance/vectors/valid-chain.json" "$KR"
run_case "vectors valid-chain no-keyring (UNVERIFIED)"       "conformance/vectors/valid-chain.json"
run_case "vectors valid-chain + keyring + checkpoint (VALID)" "conformance/vectors/valid-chain.json" "$KR" --checkpoint "$CP"

echo "== conformance/vectors/attack (integrity/security) =="
run_case "attack tampered-content (TAMPERED)"                "conformance/vectors/attack/tampered-content.json" "$KR"
run_case "attack forged-genesis (TAMPERED)"                  "conformance/vectors/attack/forged-genesis.json" "$KR"
run_case "attack key-swap (TAMPERED)"                        "conformance/vectors/attack/key-swap.json" "$KR"
run_case "attack key-swap-resigned (TAMPERED)"              "conformance/vectors/attack/key-swap-resigned.json" "$KR"
run_case "attack unknown-kid + keyring (TAMPERED)"          "conformance/vectors/attack/unknown-kid.json" "$KR"
run_case "attack unknown-kid no-keyring (UNVERIFIED)"       "conformance/vectors/attack/unknown-kid.json"
run_case "attack seq-gap (TAMPERED)"                        "conformance/vectors/attack/seq-gap.json" "$KR"
run_case "attack head-truncated (TAMPERED)"                "conformance/vectors/attack/head-truncated.json" "$KR"
run_case "attack cross-chain-splice (TAMPERED)"            "conformance/vectors/attack/cross-chain-splice.json" "$KR"
# Cross-tenant splice laundered through an OPTIONAL-field omission, and the two legitimate
# absent<->present transitions that must STAY valid (see scripts/gen-vectors.ts 5d).
run_case "attack tenant-splice-via-absent (TAMPERED)"      "conformance/vectors/attack/tenant-splice-via-absent.json" "$KR"
run_case "attack tenant-splice-via-absent-long (TAMPERED)" "conformance/vectors/attack/tenant-splice-via-absent-long.json" "$KR"
run_case "tenant-omission-then-same-tenant (VALID)"        "conformance/vectors/tenant-omission-then-same-tenant.json" "$KR"
run_case "tenant-enrichment-absent-first (VALID)"          "conformance/vectors/tenant-enrichment-absent-first.json" "$KR"
# CROSS-FIELD COHERENCE (2026-08-14): cryptographically PERFECT receipts whose SIGNED BODY
# contradicts itself — VALID in all five verifiers before these rules landed. MALFORMED, decided
# with no key material at all. The three companions pin the other half: a rule that refuses every
# receipt is an outage, and the leap second (23:59:60) is a real instant.
run_case "attack coherence-sandbox-principal (MALFORMED)"    "conformance/vectors/attack/coherence-sandbox-principal.json" "$KR"
run_case "attack coherence-simulated-not-sandboxed (MALFORMED)" "conformance/vectors/attack/coherence-simulated-not-sandboxed.json" "$KR"
run_case "attack coherence-irreversible-with-rollbackref (MALFORMED)" "conformance/vectors/attack/coherence-irreversible-with-rollbackref.json" "$KR"
run_case "attack coherence-rolled-back-irreversible (MALFORMED)" "conformance/vectors/attack/coherence-rolled-back-irreversible.json" "$KR"
run_case "attack coherence-ts-not-an-instant (MALFORMED)"    "conformance/vectors/attack/coherence-ts-not-an-instant.json" "$KR"
run_case "coherence-consistent-sandbox (VALID)"              "conformance/vectors/coherence-consistent-sandbox.json" "$KR"
run_case "coherence-rolled-back-consistent (VALID)"          "conformance/vectors/coherence-rolled-back-consistent.json" "$KR"
run_case "ts-leap-second (VALID)"                            "conformance/vectors/ts-leap-second.json" "$KR"
run_case "attack dup-seq (TAMPERED)"                        "conformance/vectors/attack/dup-seq.json" "$KR"
run_case "attack wrong-signature (TAMPERED)"                "conformance/vectors/attack/wrong-signature.json" "$KR"
run_case "attack relinked (TAMPERED)"                        "conformance/vectors/attack/relinked.json" "$KR"
run_case "attack tail-truncated + checkpoint (TAMPERED)"    "conformance/vectors/attack/tail-truncated.json" "$KR" --checkpoint "$CP"
run_case "attack tail-truncated no-checkpoint (VALID)"      "conformance/vectors/attack/tail-truncated.json" "$KR"
run_case "attack forged-checkpoint-chain + forged-cp (TAMPERED)" "conformance/vectors/attack/forged-checkpoint-chain.json" "$KR" --checkpoint "conformance/vectors/attack/forged-checkpoint-cp.json"

echo "== conformance/vectors/strict-ed25519 (refused at key load / non-canonical S) =="
# STRICT Ed25519 KEY AND SCALAR VALIDATION (scripts/gen-vectors.ts 11). Each keyring maps the corpus kid to a
# public key that strict public-key validation refuses at key load (non-canonical or small-order encoding,
# RFC 8032 §5.1.3 decoding + small-order rejection); the chain is genuine, so every case must be TAMPERED.
SE="conformance/vectors/strict-ed25519"
run_case "strict-ed25519/low-order pubkey #0 (identity) (TAMPERED)" "conformance/vectors/valid-chain.json" "$SE/keyring-low-order-0.json"
run_case "strict-ed25519/low-order pubkey #1 (order 2) (TAMPERED)" "conformance/vectors/valid-chain.json" "$SE/keyring-low-order-1.json"
run_case "strict-ed25519/low-order pubkey #2 (order 4) (TAMPERED)" "conformance/vectors/valid-chain.json" "$SE/keyring-low-order-2.json"
run_case "strict-ed25519/low-order pubkey #3 (order 4) (TAMPERED)" "conformance/vectors/valid-chain.json" "$SE/keyring-low-order-3.json"
run_case "strict-ed25519/low-order pubkey #4 (order 8) (TAMPERED)" "conformance/vectors/valid-chain.json" "$SE/keyring-low-order-4.json"
run_case "strict-ed25519/low-order pubkey #5 (order 8) (TAMPERED)" "conformance/vectors/valid-chain.json" "$SE/keyring-low-order-5.json"
run_case "strict-ed25519/low-order pubkey #6 (order 8) (TAMPERED)" "conformance/vectors/valid-chain.json" "$SE/keyring-low-order-6.json"
run_case "strict-ed25519/low-order pubkey #7 (order 8) (TAMPERED)" "conformance/vectors/valid-chain.json" "$SE/keyring-low-order-7.json"
run_case "strict-ed25519/x0-sign y=1 non-canonical pubkey (TAMPERED)" "conformance/vectors/valid-chain.json" "$SE/keyring-x0-sign-y-1.json"
run_case "strict-ed25519/x0-sign y=p-1 non-canonical pubkey (TAMPERED)" "conformance/vectors/valid-chain.json" "$SE/keyring-x0-sign-y-p-minus-1.json"
run_case "strict-ed25519/y=p non-canonical pubkey (TAMPERED)" "conformance/vectors/valid-chain.json" "$SE/keyring-y-p-sign.json"
run_case "strict-ed25519/y=p+1 non-canonical pubkey (TAMPERED)" "conformance/vectors/valid-chain.json" "$SE/keyring-y-p-plus-1.json"
run_case "strict-ed25519/off-curve pubkey y=2 (TAMPERED)" "conformance/vectors/valid-chain.json" "$SE/keyring-off-curve-y-2.json"
run_case "strict-ed25519/mixed-order pubkey (TAMPERED)" "conformance/vectors/valid-chain.json" "$SE/keyring-mixed-order.json"
run_case "strict-ed25519/s-not-canonical malleability + kr (TAMPERED)" "$SE/chain-s-not-canonical.json" "$KR"
echo
echo "== conformance/vectors/ts-order (warning parity; every chain stays VALID) =="
warn_selftest
TO="conformance/vectors/ts-order"
run_warn_case "ts-order/backwards-one-second + kr"     "$TO/backwards-one-second.json" "$KR"
run_warn_case "ts-order/backwards-one-nanosecond + kr" "$TO/backwards-one-nanosecond.json" "$KR"
run_warn_case "ts-order/backwards-after-offset + kr"   "$TO/backwards-after-offset.json" "$KR"
run_warn_case "ts-order/equal-instant + kr"            "$TO/equal-instant.json" "$KR"
run_warn_case "ts-order/second-60-ordered + kr"        "$TO/second-60-ordered.json" "$KR"
run_warn_case "ts-order/not-comparable-second-60 + kr" "$TO/not-comparable-second-60.json" "$KR"
run_warn_case "ts-order/backwards-one-second (no keyring)" "$TO/backwards-one-second.json"
run_warn_case "ts-order/second-60-then-next-minute + kr"      "$TO/second-60-then-next-minute.json" "$KR"
run_warn_case "ts-order/not-comparable-second-60-equal + kr"  "$TO/not-comparable-second-60-equal.json" "$KR"
run_warn_case "ts-order/not-comparable-real-leap-second + kr" "$TO/not-comparable-real-leap-second.json" "$KR"
run_warn_case "ts-order/year-boundary-positive-offset + kr"   "$TO/year-boundary-positive-offset.json" "$KR"
run_warn_case "ts-order/month-boundary-negative-offset + kr"  "$TO/month-boundary-negative-offset.json" "$KR"
run_warn_case "ts-order/leap-day-positive-offset + kr"        "$TO/leap-day-positive-offset.json" "$KR"
# Two warnings in one run, in seq order; the shuffled file stores the same receipts in the array order
# seq 1, seq 2, seq 0, and verifiers order by chain.seq, so both must print the same two codes.
run_warn_case "ts-order/backwards-twice + kr"                 "$TO/backwards-twice.json" "$KR"
run_warn_case "ts-order/backwards-twice-shuffled + kr"        "$TO/backwards-twice-shuffled.json" "$KR"
# ANTI-VACUITY: if the extraction matched nothing anywhere, every case above would "agree" on an
# empty list. Eleven of those cases must carry an impl-py warning, so zero is a broken runner.
if [ "$WARN_SEEN" -eq 0 ]; then
  TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
  printf '  WARN-FAIL  vacuous: impl-py printed no timestamp-order warning on any ts-order case\n'
fi
echo
echo "== conformance/vectors/independent-fields (accepted as written; exit-code and warning parity) =="
# Spec §2 "Independent fields" (scripts/gen-vectors.ts 10d): field combinations this version deliberately
# does not couple. impl-py/conformance.mjs pins impl-py at VALID with no timestamp-order warning; parity
# holds impl-csharp to the same. WARN- lines, like the ts-order cases, so the verdict matrix is unchanged.
IND="conformance/vectors/independent-fields"
run_warn_case "independent-fields/risk-class-vs-reversible + kr"     "$IND/risk-class-vs-reversible.json" "$KR"
run_warn_case "independent-fields/mode-vs-verdict-and-approval + kr" "$IND/mode-vs-verdict-and-approval.json" "$KR"
run_warn_case "independent-fields/compliance-deny-vs-executed + kr"  "$IND/compliance-deny-vs-executed.json" "$KR"
run_warn_case "independent-fields/approval-at-after-ts + kr"         "$IND/approval-at-after-ts.json" "$KR"
echo
echo "== conformance/vectors/malformed (parser/structural rejects) =="
for f in deep-nest duplicate-key float-number lone-high-surrogate lone-low-surrogate pii-smuggle proto-pollution reversed-surrogate-pair trailing-garbage; do
  run_case "malformed $f (MALFORMED)" "conformance/vectors/malformed/$f.json" "$KR"
done

echo
echo "excluded (non-receipt fixtures — consumed as auxiliary inputs, not standalone receipt chains):"
echo "  - conformance/vectors/keyring.json                     : keyring (kid -> SPKI)"
echo "  - conformance/vectors/checkpoint.json                  : signed checkpoint"
echo "  - conformance/vectors/attack/forged-checkpoint-cp.json : signed checkpoint (aux for forged-checkpoint-chain)"
echo "  - conformance/vectors/strict-ed25519/keyring-*.json   : keyrings holding refused keys (aux for valid-chain)"
echo "  - conformance/golden/0.3.0/*/keyring.json              : keyrings"
echo "  - conformance/golden/0.3.0/identity/manifest.json      : identity manifest"
echo "  - conformance/golden/0.3.0/multi/checkpoint.json       : signed checkpoint"
echo "  - conformance/golden/0.3.0/MANIFEST.json, README.md    : metadata/docs"
echo "  - conformance/federation/*, conformance/l2/*           : out of scope (separate L2/federation profiles, not receipt-chain CLI vectors)"

echo
echo "TOTAL=$TOTAL  PASS=$PASS  FAIL=$FAIL"
if [ "$FAIL" -ne 0 ]; then
  echo "CONFORMANCE FAILED: $FAIL vector(s) disagree with impl-py"
  exit 1
fi
echo "CONFORMANCE PASS: C# verifier agrees with impl-py on all $TOTAL receipt vectors"
exit 0
