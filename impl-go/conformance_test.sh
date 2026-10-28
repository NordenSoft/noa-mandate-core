#!/usr/bin/env bash
#
# Conformance runner for the from-scratch Go verifier (#41).
#
# Ground truth = impl-py/noa_verify.py, the SECOND independent verifier (its own JCS + its own
# RFC-8032 Ed25519, no shared crypto with the TS reference). For every RECEIPT-vector in
# conformance/golden/0.3.0 + conformance/vectors (incl. attack/ and malformed/) this runs BOTH
# `python3 impl-py/noa_verify.py <args>` AND `impl-go/noa-verify <args>` with IDENTICAL arguments
# and asserts the process EXIT CODES match (0 VALID · 1 UNVERIFIED · 2 TAMPERED · 3 MALFORMED ·
# 5 UNTRUSTED). One mismatch fails the whole run (no partial credit — a single divergence on a
# security verdict is a conformance failure).
#
# Non-receipt fixtures (keyrings, identity manifests, checkpoints, MANIFEST.json, README.md) are
# NOT run as receipt-vectors — they are the auxiliary trust inputs paired with the chains below,
# per conformance/golden/0.3.0/MANIFEST.json + test/verify.test.ts.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"
CONF="$REPO/conformance"
PY_SCRIPT="$REPO/impl-py/noa_verify.py"
GO_BIN="$SCRIPT_DIR/noa-verify"

GO="${GO:-go}"
( cd "$SCRIPT_DIR" && "$GO" build -o noa-verify . ) || { echo "go build failed"; exit 1; }

# The Go unit suite (jcs_test.go byte-parity + schema_test.go cross-field coherence) runs HERE, in
# the one script CI actually invokes for this implementation. Before this line `go test` existed in
# the tree and was executed by nothing — a test nobody runs is a comment. A unit failure fails the
# whole conformance run: the vectors below prove agreement WITH impl-py, the unit tests prove the
# rules the vectors cannot reach (every boundary of the calendar layer, one field at a time).
( cd "$SCRIPT_DIR" && "$GO" test ./... ) || { echo "go unit tests FAILED"; exit 1; }

G="$CONF/golden/0.3.0"
V="$CONF/vectors"

pass=0
fail=0
total=0
warn_seen=0 # warning-parity cases on which impl-py printed at least one timestamp-order warning

run_case() {
	local label="$1"
	shift
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
			printf '	FAIL	MISSING VECTOR FILE: %s	(%s)\n' "$__arg" "$label"
			return
		fi
	done
	python3 "$PY_SCRIPT" "$@" >/dev/null 2>&1
	local pyc=$?
	"$GO_BIN" "$@" >/dev/null 2>&1
	local goc=$?
	total=$((total + 1))
	if [ "$pyc" -eq "$goc" ]; then
		pass=$((pass + 1))
		printf 'PASS  py=%s go=%s  %s\n' "$pyc" "$goc" "$label"
	else
		fail=$((fail + 1))
		printf 'FAIL  py=%s go=%s  %s\n' "$pyc" "$goc" "$label"
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
WARN_PARITY="$CONF/warning-parity.py"
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
	total=$((total + 1))
	if ! out="$(python3 "$WARN_PARITY" --selftest 2>&1)"; then
		printf '%s\n' "$out"
		fail=$((fail + 1)); printf 'WARN-FAIL  self-test: conformance/warning-parity.py --selftest failed\n'
	elif ! warn_agree "$good" "$good"; then
		fail=$((fail + 1)); printf 'WARN-FAIL  self-test: two identical correct results did not agree [%s] [%s]\n' "$WARN_REF" "$WARN_PORT"
	elif warn_agree "$good" "$bad"; then
		fail=$((fail + 1)); printf 'WARN-FAIL  self-test: a string in place of the warnings array was accepted [%s]\n' "$WARN_PORT"
	else
		pass=$((pass + 1)); printf 'WARN-PASS  self-test: a string in place of the warnings array fails the comparison [%s]\n' "$WARN_PORT"
	fi
}

run_warn_case() {
	local label="$1"
	shift
	local __arg pyout goout pyc goc agree
	for __arg in "$@"; do
		case "$__arg" in
			--*) continue ;;
		esac
		if [ ! -f "$__arg" ]; then
			total=$((total + 1)); fail=$((fail + 1))
			printf 'WARN-FAIL  MISSING VECTOR FILE: %s  (%s)\n' "$__arg" "$label"
			return
		fi
	done
	pyout="$(python3 "$PY_SCRIPT" "$@" 2>/dev/null)"
	pyc=$?
	goout="$("$GO_BIN" "$@" 2>/dev/null)"
	goc=$?
	warn_agree "$pyout" "$goout"
	agree=$?
	case "$WARN_REF" in '["'*) warn_seen=$((warn_seen + 1)) ;; esac
	total=$((total + 1))
	if [ "$pyc" -eq "$goc" ] && [ "$agree" -eq 0 ]; then
		pass=$((pass + 1))
		printf 'WARN-PASS  py=%s go=%s  %s  %s\n' "$pyc" "$goc" "$WARN_REF" "$label"
	else
		fail=$((fail + 1))
		printf 'WARN-FAIL  py=%s %s  go=%s %s  %s\n' "$pyc" "$WARN_REF" "$goc" "$WARN_PORT" "$label"
	fi
}

echo "=== GOLDEN 0.3.0 (cross-version signed artifacts) ==="
run_case "golden/genesis + keyring"                       "$G/genesis/chain.json" "$G/genesis/keyring.json"
run_case "golden/genesis (no keyring)"                    "$G/genesis/chain.json"
run_case "golden/multi + keyring"                         "$G/multi/chain.json" "$G/multi/keyring.json"
run_case "golden/multi (no keyring)"                      "$G/multi/chain.json"
run_case "golden/multi + keyring + checkpoint"            "$G/multi/chain.json" "$G/multi/keyring.json" --checkpoint "$G/multi/checkpoint.json"
run_case "golden/identity + keyring + manifest"           "$G/identity/chain.json" "$G/identity/keyring.json" --identity "$G/identity/manifest.json"
run_case "golden/identity + keyring (kid-level)"          "$G/identity/chain.json" "$G/identity/keyring.json"
run_case "golden/impersonation + keyring (kid-level)"     "$G/identity/impersonation-chain.json" "$G/identity/keyring.json"
run_case "golden/impersonation + keyring + manifest"      "$G/identity/impersonation-chain.json" "$G/identity/keyring.json" --identity "$G/identity/manifest.json"

echo "=== VECTORS: valid chain ==="
run_case "valid-chain + keyring"                          "$V/valid-chain.json" "$V/keyring.json"
run_case "valid-chain (no keyring)"                       "$V/valid-chain.json"
run_case "valid-chain + keyring + checkpoint"             "$V/valid-chain.json" "$V/keyring.json" --checkpoint "$V/checkpoint.json"

echo "=== VECTORS: attack (must all reject) ==="
run_case "attack/tampered-content + keyring"             "$V/attack/tampered-content.json" "$V/keyring.json"
run_case "attack/forged-genesis + keyring"               "$V/attack/forged-genesis.json" "$V/keyring.json"
run_case "attack/key-swap + keyring"                     "$V/attack/key-swap.json" "$V/keyring.json"
run_case "attack/key-swap-resigned + keyring"            "$V/attack/key-swap-resigned.json" "$V/keyring.json"
run_case "attack/unknown-kid + keyring"                  "$V/attack/unknown-kid.json" "$V/keyring.json"
run_case "attack/unknown-kid (no keyring)"               "$V/attack/unknown-kid.json"
run_case "attack/seq-gap + keyring"                      "$V/attack/seq-gap.json" "$V/keyring.json"
run_case "attack/head-truncated + keyring"               "$V/attack/head-truncated.json" "$V/keyring.json"
run_case "attack/cross-chain-splice + keyring"           "$V/attack/cross-chain-splice.json" "$V/keyring.json"
# Cross-tenant splice laundered through an OPTIONAL-field omission, and the two legitimate
# absent<->present transitions that must STAY valid (see scripts/gen-vectors.ts 5d).
run_case "attack/tenant-splice-via-absent + keyring"     "$V/attack/tenant-splice-via-absent.json" "$V/keyring.json"
run_case "attack/tenant-splice-via-absent-long + kr"     "$V/attack/tenant-splice-via-absent-long.json" "$V/keyring.json"
run_case "tenant-omission-then-same-tenant + keyring"    "$V/tenant-omission-then-same-tenant.json" "$V/keyring.json"
run_case "tenant-enrichment-absent-first + keyring"      "$V/tenant-enrichment-absent-first.json" "$V/keyring.json"
# CROSS-FIELD COHERENCE (2026-08-14): five cryptographically PERFECT receipts — hash recomputed,
# signature genuine, linkage intact — whose SIGNED BODY contradicts itself. All five verified VALID
# in all five implementations before these rules landed. MALFORMED (exit 3), decided with no key
# material at all. The three companions below must STAY VALID: a rule that refuses every receipt is
# an outage, and the leap second (23:59:60) is a real instant.
run_case "attack/coherence-sandbox-principal + kr"      "$V/attack/coherence-sandbox-principal.json" "$V/keyring.json"
run_case "attack/coherence-simulated-not-sandboxed"     "$V/attack/coherence-simulated-not-sandboxed.json" "$V/keyring.json"
run_case "attack/coherence-irreversible-w-rollbackref"  "$V/attack/coherence-irreversible-with-rollbackref.json" "$V/keyring.json"
run_case "attack/coherence-rolled-back-irreversible"    "$V/attack/coherence-rolled-back-irreversible.json" "$V/keyring.json"
run_case "attack/coherence-ts-not-an-instant"           "$V/attack/coherence-ts-not-an-instant.json" "$V/keyring.json"
run_case "coherence-consistent-sandbox + keyring"       "$V/coherence-consistent-sandbox.json" "$V/keyring.json"
run_case "coherence-rolled-back-consistent + keyring"   "$V/coherence-rolled-back-consistent.json" "$V/keyring.json"
run_case "ts-leap-second + keyring"                     "$V/ts-leap-second.json" "$V/keyring.json"
run_case "attack/dup-seq + keyring"                      "$V/attack/dup-seq.json" "$V/keyring.json"
run_case "attack/wrong-signature + keyring"              "$V/attack/wrong-signature.json" "$V/keyring.json"
run_case "attack/wrong-signature (no keyring)"           "$V/attack/wrong-signature.json"
run_case "attack/relinked + keyring"                     "$V/attack/relinked.json" "$V/keyring.json"
run_case "attack/tail-truncated + keyring (no cp)"       "$V/attack/tail-truncated.json" "$V/keyring.json"
run_case "attack/tail-truncated + keyring + checkpoint"  "$V/attack/tail-truncated.json" "$V/keyring.json" --checkpoint "$V/checkpoint.json"
run_case "attack/forged-checkpoint + keyring + forgedcp" "$V/attack/forged-checkpoint-chain.json" "$V/keyring.json" --checkpoint "$V/attack/forged-checkpoint-cp.json"
run_case "attack/forged-checkpoint (no keyring)"         "$V/attack/forged-checkpoint-chain.json" --checkpoint "$V/attack/forged-checkpoint-cp.json"

echo "=== VECTORS: strict-ed25519 (refused at key load / non-canonical S) ==="
# STRICT Ed25519 KEY AND SCALAR VALIDATION (scripts/gen-vectors.ts 11). Each keyring maps the corpus kid to a
# public key that strict public-key validation refuses at key load (non-canonical or small-order encoding,
# RFC 8032 §5.1.3 decoding + small-order rejection); the chain is genuine, so every case must be TAMPERED.
SE="$V/strict-ed25519"
run_case "strict-ed25519/low-order pubkey #0 (identity)" "$V/valid-chain.json" "$SE/keyring-low-order-0.json"
run_case "strict-ed25519/low-order pubkey #1 (order 2)" "$V/valid-chain.json" "$SE/keyring-low-order-1.json"
run_case "strict-ed25519/low-order pubkey #2 (order 4)" "$V/valid-chain.json" "$SE/keyring-low-order-2.json"
run_case "strict-ed25519/low-order pubkey #3 (order 4)" "$V/valid-chain.json" "$SE/keyring-low-order-3.json"
run_case "strict-ed25519/low-order pubkey #4 (order 8)" "$V/valid-chain.json" "$SE/keyring-low-order-4.json"
run_case "strict-ed25519/low-order pubkey #5 (order 8)" "$V/valid-chain.json" "$SE/keyring-low-order-5.json"
run_case "strict-ed25519/low-order pubkey #6 (order 8)" "$V/valid-chain.json" "$SE/keyring-low-order-6.json"
run_case "strict-ed25519/low-order pubkey #7 (order 8)" "$V/valid-chain.json" "$SE/keyring-low-order-7.json"
run_case "strict-ed25519/x0-sign y=1 non-canonical pubkey" "$V/valid-chain.json" "$SE/keyring-x0-sign-y-1.json"
run_case "strict-ed25519/x0-sign y=p-1 non-canonical pubkey" "$V/valid-chain.json" "$SE/keyring-x0-sign-y-p-minus-1.json"
run_case "strict-ed25519/y=p non-canonical pubkey" "$V/valid-chain.json" "$SE/keyring-y-p-sign.json"
run_case "strict-ed25519/y=p+1 non-canonical pubkey" "$V/valid-chain.json" "$SE/keyring-y-p-plus-1.json"
run_case "strict-ed25519/off-curve pubkey y=2" "$V/valid-chain.json" "$SE/keyring-off-curve-y-2.json"
run_case "strict-ed25519/mixed-order pubkey" "$V/valid-chain.json" "$SE/keyring-mixed-order.json"
run_case "strict-ed25519/s-not-canonical malleability + kr" "$SE/chain-s-not-canonical.json" "$V/keyring.json"

echo "=== VECTORS: ts-order (warning parity; every chain stays VALID) ==="
warn_selftest
TO="$V/ts-order"
run_warn_case "ts-order/backwards-one-second + keyring"     "$TO/backwards-one-second.json" "$V/keyring.json"
run_warn_case "ts-order/backwards-one-nanosecond + keyring" "$TO/backwards-one-nanosecond.json" "$V/keyring.json"
run_warn_case "ts-order/backwards-after-offset + keyring"   "$TO/backwards-after-offset.json" "$V/keyring.json"
run_warn_case "ts-order/equal-instant + keyring"            "$TO/equal-instant.json" "$V/keyring.json"
run_warn_case "ts-order/second-60-ordered + keyring"        "$TO/second-60-ordered.json" "$V/keyring.json"
run_warn_case "ts-order/not-comparable-second-60 + keyring" "$TO/not-comparable-second-60.json" "$V/keyring.json"
run_warn_case "ts-order/backwards-one-second (no keyring)"  "$TO/backwards-one-second.json"
run_warn_case "ts-order/second-60-then-next-minute + keyring"      "$TO/second-60-then-next-minute.json" "$V/keyring.json"
run_warn_case "ts-order/not-comparable-second-60-equal + keyring"  "$TO/not-comparable-second-60-equal.json" "$V/keyring.json"
run_warn_case "ts-order/not-comparable-real-leap-second + keyring" "$TO/not-comparable-real-leap-second.json" "$V/keyring.json"
run_warn_case "ts-order/year-boundary-positive-offset + keyring"   "$TO/year-boundary-positive-offset.json" "$V/keyring.json"
run_warn_case "ts-order/month-boundary-negative-offset + keyring"  "$TO/month-boundary-negative-offset.json" "$V/keyring.json"
run_warn_case "ts-order/leap-day-positive-offset + keyring"        "$TO/leap-day-positive-offset.json" "$V/keyring.json"
# Two warnings in one run, in seq order; the shuffled file stores the same receipts in the array order
# seq 1, seq 2, seq 0, and verifiers order by chain.seq, so both must print the same two codes.
run_warn_case "ts-order/backwards-twice + keyring"                 "$TO/backwards-twice.json" "$V/keyring.json"
run_warn_case "ts-order/backwards-twice-shuffled + keyring"        "$TO/backwards-twice-shuffled.json" "$V/keyring.json"
# ANTI-VACUITY: if the extraction matched nothing anywhere, every case above would "agree" on an
# empty list. Eleven of those cases must carry an impl-py warning, so zero is a broken runner.
if [ "$warn_seen" -eq 0 ]; then
	total=$((total + 1)); fail=$((fail + 1))
	printf 'WARN-FAIL  vacuous: impl-py printed no timestamp-order warning on any ts-order case\n'
fi

echo "=== VECTORS: independent-fields (accepted as written; exit-code and warning parity) ==="
# Spec §2 "Independent fields" (scripts/gen-vectors.ts 10d): field combinations this version deliberately
# does not couple. impl-py/conformance.mjs pins impl-py at VALID with no timestamp-order warning; parity
# holds impl-go to the same. WARN- lines, like the ts-order cases, so the verdict matrix is unchanged.
IND="$V/independent-fields"
run_warn_case "independent-fields/risk-class-vs-reversible + keyring"     "$IND/risk-class-vs-reversible.json" "$V/keyring.json"
run_warn_case "independent-fields/mode-vs-verdict-and-approval + keyring" "$IND/mode-vs-verdict-and-approval.json" "$V/keyring.json"
run_warn_case "independent-fields/compliance-deny-vs-executed + keyring"  "$IND/compliance-deny-vs-executed.json" "$V/keyring.json"
run_warn_case "independent-fields/approval-at-after-ts + keyring"         "$IND/approval-at-after-ts.json" "$V/keyring.json"

echo "=== VECTORS: malformed (strict parse / structural rejects) ==="
run_case "malformed/deep-nest"                           "$V/malformed/deep-nest.json"
run_case "malformed/duplicate-key"                       "$V/malformed/duplicate-key.json"
run_case "malformed/float-number"                        "$V/malformed/float-number.json"
run_case "malformed/lone-high-surrogate"                 "$V/malformed/lone-high-surrogate.json"
run_case "malformed/lone-low-surrogate"                  "$V/malformed/lone-low-surrogate.json"
run_case "malformed/pii-smuggle + keyring"               "$V/malformed/pii-smuggle.json" "$V/keyring.json"
run_case "malformed/proto-pollution"                     "$V/malformed/proto-pollution.json"
run_case "malformed/reversed-surrogate-pair"             "$V/malformed/reversed-surrogate-pair.json"
run_case "malformed/trailing-garbage"                    "$V/malformed/trailing-garbage.json"

echo "=== VECTORS: strict-bytes (opt-in --profile strict-bytes; native unchanged) ==="
# scripts/gen-vectors.ts section 12. Each case runs BOTH verifiers with identical arguments twice over:
# a parity line (PASS/FAIL, counted by scripts/conformance-matrix.mjs as class strict-bytes) and a
# STRICT- line that holds BOTH exit codes to the manifest's AUTHORED expectation and, where one is
# pinned, BOTH results' detail to the NON_CANONICAL_BYTES discriminator — fixed expectations, not
# parity alone. conformance/strict-bytes-cases.py refuses a missing manifest, a missing or altered file
# and an absent case, which fails this run instead of passing on zero cases.
SB_HELPER="$CONF/strict-bytes-cases.py"
SB_MANIFEST="$V/strict-bytes/manifest.json"

# strict_expect <label> <want exit> <want discriminator: NON_CANONICAL_BYTES | - (valid result, not asserted) | none (usage, no result)> <arg...>
strict_expect() {
	local label="$1" want="$2" wdisc="$3"
	shift 3
	local pyout goout pyc goc pyd god ok
	pyout="$(python3 "$PY_SCRIPT" "$@" 2>/dev/null)"
	pyc=$?
	goout="$("$GO_BIN" "$@" 2>/dev/null)"
	goc=$?
	total=$((total + 1))
	if [ "$pyc" -eq "$goc" ]; then
		pass=$((pass + 1))
		printf 'PASS  py=%s go=%s  %s\n' "$pyc" "$goc" "$label"
	else
		fail=$((fail + 1))
		printf 'FAIL  py=%s go=%s  %s\n' "$pyc" "$goc" "$label"
	fi
	pyd="-"; god="-"
	if [ "$wdisc" != "none" ]; then
		pyd="$(python3 "$SB_HELPER" disc "$pyout")"
		god="$(python3 "$SB_HELPER" disc "$goout")"
	fi
	ok=1
	[ "$pyc" -eq "$want" ] && [ "$goc" -eq "$want" ] || ok=0
	[ "$pyd" != "INVALID" ] && [ "$god" != "INVALID" ] || ok=0
	if [ "$wdisc" = "NON_CANONICAL_BYTES" ]; then
		[ "$pyd" = "$wdisc" ] && [ "$god" = "$wdisc" ] || ok=0
	fi
	total=$((total + 1))
	if [ "$ok" -eq 1 ]; then
		pass=$((pass + 1))
		printf 'STRICT-PASS  want=%s %s  py=%s %s  go=%s %s  %s\n' "$want" "$wdisc" "$pyc" "$pyd" "$goc" "$god" "$label"
	else
		fail=$((fail + 1))
		printf 'STRICT-FAIL  want=%s %s  py=%s %s  go=%s %s  %s\n' "$want" "$wdisc" "$pyc" "$pyd" "$goc" "$god" "$label"
	fi
}

if ! SB_CASES="$(python3 "$SB_HELPER" list "$SB_MANIFEST")"; then
	total=$((total + 1)); fail=$((fail + 1))
	printf 'STRICT-FAIL  corpus: %s is missing, altered or not the authored case set\n' "$SB_MANIFEST"
else
	while IFS=$'\t' read -r sb_name sb_file sb_kr sb_native sb_strict sb_disc; do
		[ -n "$sb_name" ] || continue
		strict_expect "strict-bytes/$sb_name --profile strict-bytes + keyring" "$sb_strict" "$sb_disc" --profile strict-bytes "$sb_file" "$sb_kr"
		if [ "$sb_native" != "-" ]; then
			strict_expect "strict-bytes/$sb_name native + keyring" "$sb_native" "-" "$sb_file" "$sb_kr"
		fi
	done <<< "$SB_CASES"
fi
SB_CANON="$V/strict-bytes/canonical.json"
strict_expect "strict-bytes usage: --profile without a value"          4 none "$SB_CANON" --profile
strict_expect "strict-bytes usage: unknown --profile value"            4 none --profile strict "$SB_CANON"
strict_expect "strict-bytes usage: repeated --profile"                 4 none --profile native --profile strict-bytes "$SB_CANON"
strict_expect "strict-bytes usage: with --purpose historical"          4 none --profile strict-bytes --purpose historical "$SB_CANON" "$V/keyring.json"

echo "=== AUX fixtures fed as receipts -> both MALFORMED (non-array top-level) ==="
run_case "aux/vectors keyring as receipts"               "$V/keyring.json"
run_case "aux/vectors checkpoint as receipts"            "$V/checkpoint.json"
run_case "aux/attack forged-cp as receipts"              "$V/attack/forged-checkpoint-cp.json"
run_case "aux/golden multi checkpoint as receipts"       "$G/multi/checkpoint.json"
run_case "aux/golden identity manifest as receipts"      "$G/identity/manifest.json"

echo "----------------------------------------"
printf 'TOTAL %s  PASS %s  FAIL %s\n' "$total" "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
echo "CONFORMANT: impl-go matches impl-py on all $total cases"
