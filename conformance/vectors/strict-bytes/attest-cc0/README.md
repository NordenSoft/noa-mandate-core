# attest-cc0: an outside implementer's receipt vectors (vendored, CC0)

Twelve `noa.receipt/0.1` receipt vectors written by Maxim for his independent verifier,
[mrpkk/attest](https://github.com/mrpkk/attest). Thank you, Maxim, for the corpus and for the report that led to
the opt-in `strict-bytes` profile.

## Provenance

| File | Upstream path | Upstream commit | SHA-256 |
|---|---|---|---|
| `receipt-vectors.json` | `conformance/receipt-vectors.json` | `e6ec711b5da367d91d1e8489106d406f47d98cd7` | `d57b0673b7cf1320ab06ca84459e208855dc981ab7ca493d4425dcd800916261` |
| `LICENSE` | `conformance/LICENSE` | `e6ec711b5da367d91d1e8489106d406f47d98cd7` | `03c6c2d74d88d05f4a0ed216aeb088e22b828388ed82672cd426ac53a57d31bd` |

Both files are byte-for-byte the upstream files (their git blob ids equal the upstream tree's). They are vendored,
not generated: `scripts/gen-vectors.ts` carries them across its clean rebuild of `conformance/vectors/` and refuses
to run when either differs from the pin above. Do not edit them; a newer upstream corpus is vendored as a new pin.
Re-checked on 2026-10-29 against upstream `main` at `08c247d9ece490f243ca2bf4305dbe0fbb44635b`: both files
are unchanged there (same git blob ids and SHA-256), so the pin above stands.

## Licence

The two upstream files are dedicated to the public domain under CC0 1.0 Universal; `LICENSE` is the upstream
notice, kept unchanged. CC0 asks for no attribution; the credit above is a courtesy.

## How the core runs them

`impl-py/conformance.mjs` (section 16) checks the pin, then for each vector builds the bare chain
`"[" + text + "]"` (the UTF-8 JCS form of a one-receipt array when `text` is canonical) and the keyring
`{"k1": SPKI(public_key)}` (the 12-byte Ed25519 SPKI prefix before the corpus's raw 32-byte key), and runs both
the TypeScript `verifyChain` and the Python verifier with `--profile strict-bytes`.

The expectation is the corpus's own `expect_ok`, read from the vendored file and never from a verifier run:

- `expect_ok: true` must be `VALID` (exit 0);
- `expect_ok: false` must be a refusal of the receipt's own bytes, `TAMPERED` (exit 2) or `MALFORMED` (exit 3).
  `UNVERIFIED` or `UNTRUSTED` would mean the corpus key was not applied, so they fail the check.

`not_canonical` is the vector that needs the profile: its signature and hash are valid, but its bytes are not
the canonical serialization, so `--profile strict-bytes` refuses it while the default `native` profile does not
judge the encoding.

The vendored file states only `expect_ok`. For `not_canonical` the corpus author also stated the exact outcome
under strict-bytes: `MALFORMED`, `detail` (TypeScript `reason`) starting `NON_CANONICAL_BYTES`, exit 3, not
`TAMPERED`. Section 16 holds both verifiers to that status token and that detail prefix, and the Python verifier
to that exit code as well; it never compares the status alone for this vector. The expectation is written in the
runner (`ATTEST_CC0_STATED`), not taken from a verifier run, and agrees with `docs/receipt-spec.md` section 5.

## Scope: bare chain path only

Every vector here is a bare receipt with no COSE envelope, so the corpus exercises the bare-chain verification
path only. It is kept apart from the envelope conformance (the COSE vectors `canonical.cose` and
`extra-space.cose` one directory up, run by `test/cose/cose.test.ts`), so a failure here names the chain layer,
not the envelope.
