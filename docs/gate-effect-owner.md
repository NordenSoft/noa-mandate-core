# Effect-owned commit in the reference gate (`noa.ledger.transfer`)

Status: reference-gate behaviour for `packages/gate` (ADR-R-012, PROPOSED). It is not wire language:
no field is added to `noa.receipt/0.1` or to any side-artifact schema, and the route and error codes
below are an implementation surface of the reference gate. What this does **not** establish is listed
in [NON-CLAIMS.md](../NON-CLAIMS.md) §S9.

## Why

For `noa.command.exec` the gate issues an execution grant and the agent's wrapper runs the command: the
gate reserves the single use and then hands the grant to the agent, and the hold view shows the grant
while it is still unused. The gate never sees the effect, so it cannot bind the consumption of the
authority to the effect itself.

For an **effect-owned** action the gate commits the effect itself. The only such action is
`noa.ledger.transfer` ([docs/ledger-transfer-spec.md](ledger-transfer-spec.md)). An in-process
**effect owner** writes the ledger row, and writing that row consumes the authority in the same
synchronous step. Before the row exists the agent never holds a usable transfer authority.

## What changes for an effect-owned action

- **Registration.** The ledger adapter is registered together with a frozen `EFFECT_OWNED` table
  (`isEffectOwned`). The refusals below key on that static table, never on whether an owner happens to
  be configured, so an engine without an owner that shares the store cannot reopen them.
- **Hold creation.** In addition to every existing check:
  - a caller-supplied `action.reversible` member is refused whatever its value
    (`422 REVERSIBLE_NOT_CALLER_SUPPLIED`); the adapter derives `reversible: false` and that is the
    value the gate signs. This applies only to adapters that derive reversibility; an adapter that
    does not derive it keeps the caller-supplied flag;
  - with no owner configured the hold is refused (`503 EFFECT_OWNER_UNCONFIGURED`), so no human is
    asked to approve a transfer nothing can execute;
  - a transfer naming a ledger the configured owner does not commit is refused
    (`422 LEDGER_NOT_OWNED`). Account existence is **not** checked here: that would let the agent learn
    which accounts exist before any human approved anything.
  - the hold keeps the exact canonical text the adapter hashed, for the owner's re-derivation. It is
    never part of a view.
- **Views.** `decide` (on the `/decision` route, which is not owner-scoped), `wait` and `GET` return
  `executionGrant: null` until an EXECUTED row exists, plus an `effect` member: `null` or
  `{effectId, outcome}`. A wrapper that receives "APPROVED, no grant" fails closed.
- **`reserve` and `report`** refuse the action (`409 EFFECT_OWNED_ACTION_NOT_RESERVABLE`,
  `409 EFFECT_OWNED_ACTION_NOT_REPORTABLE`). Without the report refusal, a RESERVED grant from an
  injected store plus `DISPATCHED` would make the gate sign an EXECUTED receipt for a transfer no
  ledger recorded.

## The commit route

`POST /v1/holds/:holdId/commit`. Agent-authenticated and owner-scoped like `cancel`: a foreign hold is
the same `404 UNKNOWN_HOLD` as an absent one. No body is read. The agent's key decides only whether and
when an already-approved commit happens; the authority is the approver's decision plus the
gate-issued grant, and the owner re-verifies both.

Checks, in order (first failure wins). Store-state checks run in the engine; signed-bytes checks run in
the owner, which defends against a hostile caller of its own commit API — hostile input objects and a
hostile sealer (NON-CLAIMS.md §S9). The owner repeats the audience and epoch checks on the signed
envelope, and checks the boot twice: the boot identifier it is handed (store state, which a caller
can supply falsely) and the gate-signed freeze time against the boot's start. The one state change
before the checks is lazy expiry at step 1: an overdue PENDING hold is expired and its timeout signed,
exactly as a read of the hold does.

| # | Check | Refusal |
| --- | --- | --- |
| 1 | The caller owns the hold; then an overdue PENDING hold is expired (lazy expiry) | `404 UNKNOWN_HOLD` |
| 2 | The action is effect-owned | `409 ACTION_NOT_EFFECT_OWNED` |
| 3 | An owner is configured for it | `503 EFFECT_OWNER_UNCONFIGURED` |
| 4 | Replay first: a recorded row answers with its own result (`idempotent: true`) at any later time | `500 EFFECT_ROW_INCONSISTENT` · `409 EFFECT_AUTHORITY_CONSUMED` |
| 5 | The hold is APPROVED | `409 HOLD_NOT_APPROVED` (retryable only while PENDING) |
| 6 | The grant, decision, verdict receipt and canonical text are present | `409 HOLD_STATE_INVALID` |
| 7 | The grant is UNUSED and unreported | `409 GRANT_NOT_UNUSED` |
| 8 | Trust-root binding: roster expiry, audience, epoch ([gate-pinned-trust.md](gate-pinned-trust.md)) | `503 ROSTER_EXPIRED` · `409 GATE_AUDIENCE_MISMATCH` · `409 EPOCH_CHANGED` |
| 9 | The hold was frozen by this boot of the gate | `410 HOLD_FROM_DEAD_BOOT` |
| O0 | No other commit on this owner is in progress — from the first line to the last, so neither a getter on the input nor the sealer can re-enter; the input is read once, at entry, into a frozen snapshot (its three string members type-checked, else `input`); the stored boot identifier is this boot's | `409 EFFECT_COMMIT_REENTRANT` (retryable) · `500 COMMIT_AUTHORITY_INVALID` · `410 HOLD_FROM_DEAD_BOOT` |
| O1 | The owner verifies against its pinned trust root, in this order: the hold envelope's signature (`envelope`), tenant and gate (`envelope-audience`), hold id against the caller's (`envelope-hold`) and epoch (`envelope-epoch`); the deferred receipt the envelope binds (`deferred-binding`); the ENFORCED mode and the registered projection identities (`projection-identity`); the deferred and approval receipts' signatures and linkage under the receipt keyring (`receipt-chain`), an ALLOWED verdict (`approval-verdict`) and the held action's five members on the approval (`approval-action`); the grant's signature (`grant`) and its bindings to the hold, envelope, approval receipt and params hash (`grant-binding:<field>`); the decision's signature, role tier and binding to this envelope and tenant, evaluated at the grant's signed `issuedAt` (`decision`), and `decision = APPROVE` (`decision-not-approve`); that the approval receipt is signed by, and names, the deciding approver as a HUMAN (`approver-identity`), under the same key the decision keyring names (`keyring-consistency`); that the display the envelope binds (`display-binding`) was sealed to that approver (`display-recipient`) | `500 COMMIT_AUTHORITY_INVALID`, `detail` naming the leg |
| O1b | The gate-signed freeze time (the deferred receipt's `ts`) is not earlier than this boot's start, whatever boot identifier the caller supplied | `410 HOLD_FROM_DEAD_BOOT` |
| O2 | Uniqueness over the envelope, decision and grant keys, before anything is signed, so a replay never reaches the sealer (the keys are checked again before the write): all three on one row replays it | `409 EFFECT_AUTHORITY_CONSUMED` |
| O3 | The commit instant is before the grant's `expiresAt` and the envelope's (re-derived here) | `410 GRANT_EXPIRED` |
| O4 | The stored canonical text re-derives the params hash the grant binds | `500 PARAMS_SNAPSHOT_MISMATCH` |
| O5 | The transfer names this owner's ledger (no row is written); and it moves between two accounts | `422 LEDGER_NOT_OWNED` · `422 LEDGER_SAME_ACCOUNT` |
| O6 | Both accounts exist | `409 LEDGER_ACCOUNT_UNKNOWN` — a REFUSED row |
| O7 | The balance covers the amount (an exact digit walk over the validated string) | `409 LEDGER_INSUFFICIENT_FUNDS` — a REFUSED row |
| O8 | The attestation is signed from the owner's own verified parses, then verified before anything is written: it is bound to this commit (the receipt's `ts` and the consumption's `consumedAt` equal the commit instant handed to the sealer, with no skew; the receipt id was never recorded); the EXECUTED receipt is signed by this gate, links onto the verified approval receipt, carries exactly the verified action and scope, and every other member as the gate's sealer writes it; the consumption is signed by the execution signer and binds the verified grant and that receipt. An attestation that throws when read is refused. The uniqueness keys are checked once more immediately before the write | `503 EFFECT_SIGNER_UNAVAILABLE` (retryable) · `500 EFFECT_ATTESTATION_INVALID` · `409 EFFECT_AUTHORITY_CONSUMED`; nothing written |
| O9 | The row (the snapshot's canonical text, the envelope's hold id), both balances and the three index entries are written | `200` |

After a new EXECUTED row the grant record is marked REPORTED with the consumption. If that fails the
answer is still `200`: the row is the record, and `reserve`/`report` refuse regardless.

Error bodies are `{error, detail?, retryable}`. A REFUSED row answers
`409 {error, outcome: "REFUSED", idempotent, effectId, retryable: false}`. Success answers
`200 {outcome: "EXECUTED", idempotent, effectId, sequence, holdId, grantId, ledger, fromAccount,
toAccount, amount, unit, paramsHash, committedAt, executionGrant, executedReceipt,
executionConsumption}`. The salt, the canonical text and balances are never returned.

## What the owner signs

The EXECUTED attempt receipt (the builder `report()` uses, chained onto the approval receipt the grant
binds) and the grant's consumption with result `DISPATCHED`. The sealer (`buildEffectAttestation`)
receives only the owner's frozen, verified parses of the envelope, receipts, decision and grant — never
a live store object — so the action, scope and agent it signs are the ones the owner verified. The
owner then verifies what came back (O8) and records its own parses of it, not the returned objects.
A REFUSED row is never signed. The hold resolution keeps its reason code
`HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND`: the gate is the witness of its own effect, so no stronger
claim is made.

## Terminal states of an effect-owned hold

- **EXECUTED:** a row with a signed attempt receipt and consumption; the grant is REPORTED; the hold
  stays APPROVED.
- **REFUSED:** an unsigned, terminal row; the grant stays UNUSED. An approval covers the transfer as
  approved, so a refusal is not retried until funds appear.
- **APPROVED with no row** after the grant expires, **DENIED**, **EXPIRED** and
  **CANCELLED_LOCAL_STATE_LOST** are unchanged. No INDETERMINATE state is reachable.

## Restarts: the boot identifier

Every hold records the `bootId` of the trust root that froze it. A pinned gate keeps its key across a
restart, so a pre-restart envelope stays verifiable; without a boot check a hold frozen before a
restart could still be approved or committed after it. The boot identifier is store state, not a
signed value, and a supervisor may hand one identifier to a later boot, so a hold is this boot's only
when it records this boot's identifier AND its gate-signed freeze time is not earlier than this boot's
start (`frozenBeforeBoot`, one rule). `decide()` applies both before it parses the body (`410
HOLD_FROM_DEAD_BOOT`; nothing is signed, and the hold later expires with a signed EXPIRED), in both
trust modes and for every action; `commit()` refuses a foreign identifier at check 9, and the owner
applies both again (O0 and O1b). A supervisor that supplies `bootId` supplies the boot's start with it
(`bootStartedAt`); otherwise the boot's start is this process's clock at boot. A clock rollback, a
restart within the same millisecond, or a supervisor that reuses both its identifier and its start
instant defeats the freeze-time comparison (NON-CLAIMS.md §S9).
`reserve()` does not check the boot for command holds: the agent already holds those grants.

## Constructing an owner

`createInMemoryLedgerEffectOwner({trust, now, ledger, accounts})` builds the reference owner and its
in-memory ledger (whole `XTS` units). It refuses, and builds nothing, when the trust root is not pinned
(`EFFECT_OWNER_REQUIRES_PINNED_TRUST`: an alpha trust root keeps the approver's private key in the
gate process), or when the ledger or an account identifier fails the `noa.ledger.transfer/1`
identifier rules, a balance is not a non-negative safe integer, or the balances sum past
`Number.MAX_SAFE_INTEGER` (`EFFECT_OWNER_LEDGER_INVALID`). Pass owners as `effectOwners` to
`createGate` or `GateEngine`; the engine refuses an owner of another trust root
(`EFFECT_OWNER_TRUST_MISMATCH`), two owners for one action (`EFFECT_OWNER_DUPLICATE`) and an owner
for an action that is not effect-owned (`EFFECT_OWNER_CANONICAL_INVALID`). In one process, one engine
with owners may serve a boot (`EFFECT_OWNER_TRUST_IN_USE`, keyed on the `bootId`, so a copy of the
trust root is refused too) and an owner serves one engine (`EFFECT_OWNER_ALREADY_BOUND`): two engines
with their own owners on one boot would each keep a ledger for the same approval. The boot is reserved
only after every owner bound. The engine accepts any object that implements the owner interface: the
owner's code is trusted, its callers are not. The reference command line wires no
ledger: a ledger that resets on restart would mislead an operator.

## Building another owner: the exported checks and the conformance runner

An embedder that builds its own owner — for example one whose ledger lives in a durable store — runs
the reference owner's checks, not a copy of them:

- `verifyEffectAuthority(trust, registered, input, nowIso)`: the entry snapshot (the caller's input read
  once), the hold's boot, O1 and O1b, in that order, first failure wins. It returns the frozen input
  snapshot, the verified parses and the three uniqueness keys, or a refusal
  (`COMMIT_AUTHORITY_INVALID` with O1's token, or `HOLD_FROM_DEAD_BOOT`). The trust root's keyring is
  consumed at the one verification context behind it.
- `deriveLedgerCommit(authority, ledger, at)`: O3 to O5, pure — the expiry clamp, the params hash
  re-derived from the snapshot's canonical text, this owner's ledger, two distinct accounts. It reads
  only the verified authority, never the input again, and returns the transfer, its exact integer
  amount and the bindings the row records.
- `verifyEffectAttestation(trust, raw, verified, nowIso, alreadyRecorded)`: O8, pure — the check of what
  the sealer returned, bound to this commit's instant, with `alreadyRecorded` answering from the owner's
  record whether an EXECUTED receipt id was already recorded. It returns the first problem (or none)
  and the verified parses the row keeps.
- `prepareEffectVerification()` loads what these checks verify with; an owner calls it at construction.
- The owner keeps O0 (the whole-commit re-entry refusal: in-process state here; a durable owner must
  provide an equivalent guard at transaction level, so that nothing a callback does inside one commit
  obtains a second row), O2 (uniqueness over its own record, checked again just before the write), O6
  and O7 (its accounts and balances) and O9 (the write).
- An owner that records the grant's consumption itself, in the same step as its row, declares
  `recordsGrantConsumption: true` and its `store`. The engine refuses it at construction unless that is
  the engine's own store (`EFFECT_OWNER_STORE_MISMATCH`), and then does not mirror the consumption.
  `EFFECT_STORE_UNAVAILABLE` is an owner refusal that wrote nothing: `503`, retryable.
- Under a supervisor-supplied `bootId`, which several processes may share, the engine accepts only an
  owner that records the consumption in its store (`EFFECT_OWNER_SUPERVISOR_BOOT_UNSAFE` otherwise).
- `runEffectOwnerConformance(label, factory, storeFactory)` (`packages/gate/test/effect-owner-conformance.ts`
  in this repository) registers the reference owner's owner-level tests — its construction rules, the
  tests that call the owner directly and those that reach it through the engine's commit route —
  against the owners `factory` builds. The optional `storeFactory`, paired with `factory`, builds every
  store the runner uses (a new in-memory store when it is omitted), and the runner builds each owner
  over the store of the engine that runs it: an owner that records the grant's consumption then meets
  the construction rules instead of `EFFECT_OWNER_STORE_MISMATCH`. `test/effect-owner.test.ts` runs it
  over the in-memory owner and over the same owner recording the consumption in its paired store. One
  owner-level test is exported rather than registered: `effectOwnerKeyringProof(factory, storeFactory)`,
  the proof bound to the keyring consume site, whose marker must sit on a test registered directly in a
  test file (`test/effect-owner.test.ts` registers it for the in-memory owner; another owner's test
  file registers it the same way). Passing both shows the owner meets those tests; it does not show the
  owner is correct (NON-CLAIMS.md §S9).
- `runSettleHoldStoreContract(label, open)` (`packages/gate/test/store-settle-contract.ts`) registers the
  store-level contract of `settleHold` — a win writes the hold and its grant together, a loss writes
  nothing, of two connections that both read PENDING exactly one wins — over two connections `open`
  returns; the in-memory store and two detached views of one state run it here.

## One transition out of PENDING

Every way a hold leaves PENDING — `decide`, expiry (by a read, a long-poll or the sweep) and the
local-state-lost cancel — builds the settled record apart from the stored one and hands it to the
store's `settleHold(next, grant)`, which writes the hold and, for an approval, its grant in one step
only while the stored hold is still PENDING. A caller that loses persists nothing and returns nothing
it signed: `decide` and the cancel answer `409 HOLD_ALREADY_RESOLVED`, an expiry re-reads the hold and
shows what the store holds, and the sweep counts only the holds it expired. The in-memory store
performs the compare and the writes in one synchronous block; a durable store expresses them as one
transaction whose compare is `UPDATE … WHERE id = $id AND status = 'PENDING'`. Every hold view,
including the `201` of `createHold`, carries the gate-signed deferred receipt the envelope binds, so a
party that sees only the HTTP API can build and check the approval that chains onto it.

## What the knockout registry measures

The controls above are armed in `scripts/lint-control-knockout.mjs` (suite `npm run test:effect` in
`packages/gate`); each arm's detecting test asserts the consequence — a row, a balance, a signature,
the grant record, the signed bytes a view hands out, a hold — before any refusal code. Some arms remove
two or three checks together, because each alone refuses the same attack: the deferred binding with
the receipt chain's linkage and the approval action, the envelope's tenant check with the decision's
tenant binding, and the pre-write re-check with the whole-commit re-entry refusal. The detecting tests
of the owner's arms are in the conformance runner, whose store pairing is armed too: without it the
construction test over the owner that records the consumption fails. These checks have no arm, each
for the reason given:

- engine steps 5 and 6: a hold that is not APPROVED, or lacks its artifacts, has no approval the owner
  can verify (its decision and APPROVE legs refuse it);
- engine step 8: the owner repeats the audience and epoch checks (armed); roster expiry is not
  repeated, and bounds the grant's signed expiry at issuance, which the owner enforces (O3, armed);
- engine step 9: the owner repeats the boot check (armed);
- `EFFECT_ROW_INCONSISTENT`: unreachable, because the owner refuses a hold id other than the one the
  envelope names (armed) and records the envelope's hold id, so a row found by the envelope hash
  always names that hold;
- the envelope's signature and gate kid: a forged envelope also needs a grant bound to its hash, which
  only the execution signer signs (the grant leg is armed), and the signer-identity rule binds
  `gateKid` to the only key the keyring grants `hold-signer`;
- the envelope's mode: a RAW envelope names no projection identity, so the identity comparison
  refuses it as well;
- the deferred binding alone, each tenant check alone, and the pre-write re-check alone: armed together
  with the checks that cover them (the deferred binding with the receipt chain and the approval
  action, since a substituted deferred receipt for another amount is refused by any one of the three;
  the pre-write re-check with the whole-commit re-entry refusal, since either alone keeps a second row
  out, and the re-entry refusal alone is armed on the second signature it prevents);
- the projection-identity leg: O4 re-derives the effect with the registered kernel function whatever
  identity the envelope names;
- activation evaluated at the grant's `issuedAt`: the keyring is fixed for the boot and decide already
  enforced activation for an honest grant signer, while a dishonest one chooses `issuedAt`; the check
  stays, and the consume site's parity proof is bound to the decision-verification arm;
- the entry snapshot's type checks: a non-string member is refused by the kernel parse or by a
  comparison with signed bytes anyway (the single read itself is armed);
- the O8 legs other than the action, the instant and the shape: the whole check is armed (a sealer
  returning nothing); the others refuse attestations the gate's own sealer cannot produce from the
  verified parses it is given. The receipt-id freshness check never fires while one authority reaches
  the sealer once (O2, the re-entry refusal and the pre-write re-check, all armed);
- the refusal of an attestation that throws when read: nothing is written either way, and the refusal
  replaces an exception thrown out of `commit()`;
- the verified-parse hand-off to the sealer: a sealer reading live store state is refused by the armed
  O8 check, so the hand-off keeps honest commits working rather than keeping false evidence out;
- the decision and grant keys of O2 on their own, which follow from the envelope key and O1's
  bindings while the quorum is 1 (they are kept for larger quorums and for a durable owner);
- `LEDGER_SAME_ACCOUNT`: unreachable while the kernel refuses `TRANSFER_SAME_ACCOUNT` (armed in the
  kernel suite); kept so that conservation does not rest on one rule;
- balance overflow, which the construction bound and conservation of the total rule out;
- the engine's owner-configuration checks and the owner binding: a second engine for a bound owner is
  refused first by the boot guard (armed), and an owner shared by two engines would still write one
  row per authority (O2, armed).

The derivation of `reversible` alone is not armed either: while the member is refused, the derived
`false` equals the default. The refusal alone and the pair together are armed.
