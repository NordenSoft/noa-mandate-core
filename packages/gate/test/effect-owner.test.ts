/**
 * The in-memory reference effect owner (docs/gate-effect-owner.md, `src/effect-owner.ts`).
 *
 * Every owner-level test lives in the owner conformance runner (test/effect-owner-conformance.ts), which
 * this file runs over the in-memory owner, and over the same owner recording the grant's consumption in
 * the store it is paired with. The one test registered here directly is the proof bound to
 * the keyring consume site: the resolver's proof binding needs its marker on a test registered in a test
 * file, so the runner exports its body instead of registering it.
 *
 * Proof ID referenced by scripts/resolver-inventory.json — do not rename without updating it:
 *   [PROOF:RES-PAR-GATE-EFFECT-OWNER]
 */
import { test } from "node:test";
import { InMemoryStore } from "../src/store.js";
import { inMemoryOwnerFactory, recordingOwnerFactory } from "./helpers/effect.js";
import { effectOwnerKeyringProof, runEffectOwnerConformance } from "./effect-owner-conformance.js";

test("[PROOF:RES-PAR-GATE-EFFECT-OWNER] the owner's own keyring consume site: decisions verify only under the roster keyring, with activation at the decision's signed instant and revocation", () => {
  effectOwnerKeyringProof(inMemoryOwnerFactory);
});

// ── the owner conformance runner, over the in-memory reference owner ─────────────────────────────

runEffectOwnerConformance("in-memory", inMemoryOwnerFactory);

// ── the same runner over an owner that records the grant's consumption in its store ─────────────
// The engine refuses such an owner over any store but its own, so the runner builds every owner and
// the engine that runs it over one store from the store factory it is given.

runEffectOwnerConformance("in-memory, recording consumption", recordingOwnerFactory, () => new InMemoryStore());
