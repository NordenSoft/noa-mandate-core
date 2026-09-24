/**
 * K13 — the roster high-water lock under DETERMINISTIC interleavings of several boots.
 *
 * Each boot runs in a worker thread and stops before every filesystem call on the lock (see
 * helpers/lock-interleave.ts); a scenario is replayed once for every point at which the next boot can
 * cut in, so a race window is exercised on every run, on every platform, over the real lock code.
 *
 * The invariant is the consequence the lock exists for: at no point do two boots both hold the lock,
 * and a holder's lock file is never removed by anyone but that holder.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { LoadPinnedTrustInput } from "../src/trust.js";
import { LockActor } from "./helpers/lock-interleave.js";
import { freshDir, newWorld, rosterDoc, writeKeyFile, writeRoster } from "./helpers/pinned.js";

const NOW = Date.parse("2026-09-01T12:00:00.000Z");
const OTHER_UID = 4242;
/** The pid written into a stale lock or mutex: dead. Every actor thread shares this process's live pid. */
const DEAD_PID = 424242;
const MAX_STEPS = 40;

interface Stage {
  readonly lockPath: string;
  readonly input: Omit<LoadPinnedTrustInput, "now" | "isProcessAlive">;
}
function stage(): Stage {
  const world = newWorld();
  const dir = freshDir("lock-interleave");
  const rosterFile = writeRoster(dir, rosterDoc(world, NOW));
  const keyFile = writeKeyFile(dir, world.gate);
  const input = {
    rosterFile,
    keyFile,
    rosterSha256: undefined,
    unsafeSameUid: false,
    tenantEnv: undefined,
    grantSignerSocketSet: false,
    gateEuid: OTHER_UID,
    nowMs: NOW,
  };
  return { lockPath: `${keyFile}.roster-state.lock`, input };
}
const actors = (s: Stage, names: readonly string[]): LockActor[] => names.map((n) => new LockActor(n, s.lockPath, DEAD_PID, s.input));

/** THE CONSEQUENCE: at most one boot holds the lock, and a sole holder's lock file is still there. */
function assertOneHolder(s: Stage, all: readonly LockActor[], label: string): void {
  const holders = all.filter((a) => a.holding).map((a) => a.name);
  assert.ok(holders.length <= 1, `consequence (${label}): two boots hold the high-water lock at once: ${holders.join(", ")}`);
  if (holders.length === 1) assert.ok(existsSync(s.lockPath), `consequence (${label}): the holder ${holders[0]}'s lock was removed by another boot`);
}

async function releaseAll(all: readonly LockActor[]): Promise<void> {
  for (const a of all) {
    if (a.holding) {
      await a.start("release");
      await a.finish("release");
    }
    await a.stop();
  }
}

/** Run `scenario(k)` for k = 0, 1, … until the cut-in point lies past the end of the interrupted boot. */
async function everyCutIn(scenario: (k: number) => Promise<boolean>): Promise<number> {
  for (let k = 0; k < MAX_STEPS; k++) {
    if (!(await scenario(k))) return k + 1;
  }
  throw new Error(`the interrupted boot did not finish within ${MAX_STEPS} filesystem calls`);
}

test("[PROOF:GATE-LOCK-TAKEOVER-RECHECK] K13 interleaved takeover — A takes over the dead holder's lock while B is between its read and its takeover, and C boots at every point of B's takeover: never two holders", { timeout: 120_000 }, async () => {
  const runs = await everyCutIn(async (k) => {
    const s = stage();
    writeFileSync(s.lockPath, `${DEAD_PID}\n`, { mode: 0o600 });
    const [a, b, c] = actors(s, ["A", "B", "C"]) as [LockActor, LockActor, LockActor];
    try {
      await b.start("boot");
      await b.advance(2); // B: the exclusive create failed and the dead holder was read.
      await a.start("boot");
      await a.finish("boot"); // A takes the dead holder's lock over and holds it.
      const at = await b.advance(k); // B's takeover runs k filesystem calls ...
      await c.start("boot");
      await c.finish("boot"); // ... then C boots in full.
      await b.finish("boot");
      assertOneHolder(s, [a, b, c], `C cut in after ${k} of B's takeover calls`);
      assert.equal(a.holding, true, `consequence (k=${k}): A, which took the lock over first, must still hold it`);
      return at.type === "op";
    } finally {
      await releaseAll([a, b, c]);
    }
  });
  assert.ok(runs >= 2, "anti-vacuity: B's takeover made no filesystem call to cut into");
});

test("K13 interleaved release — A releases while B's stale takeover and C's boot run between A's read and A's delete; then D boots: never two holders", { timeout: 120_000 }, async () => {
  await everyCutIn(async (k) => {
    const s = stage();
    writeFileSync(s.lockPath, `${DEAD_PID}\n`, { mode: 0o600 });
    const [a, b, c, d] = actors(s, ["A", "B", "C", "D"]) as [LockActor, LockActor, LockActor, LockActor];
    try {
      await b.start("boot");
      await b.advance(2); // B has read the dead holder.
      await a.start("boot");
      await a.finish("boot"); // A holds.
      await a.start("release");
      await a.advance(1); // A has read its own lock back and stands before deleting it.
      const at = await b.advance(k);
      await c.start("boot");
      await c.finish("boot");
      await b.finish("boot");
      await a.finish("release"); // A's delete runs now.
      await d.start("boot");
      await d.finish("boot");
      assertOneHolder(s, [a, b, c, d], `B ran ${k} takeover calls inside A's release`);
      return at.type === "op";
    } finally {
      await releaseAll([a, b, c, d]);
    }
  });
});

test("[PROOF:GATE-LOCK-TAKEOVER-SERIALIZED] K13 two takers — B and B2 both read the dead holder; B2 is interrupted at every point of its takeover while B runs in full: never two holders", { timeout: 120_000 }, async () => {
  await everyCutIn(async (k) => {
    const s = stage();
    writeFileSync(s.lockPath, `${DEAD_PID}\n`, { mode: 0o600 });
    const [b, b2] = actors(s, ["B", "B2"]) as [LockActor, LockActor];
    try {
      await b.start("boot");
      await b.advance(2);
      await b2.start("boot");
      await b2.advance(2); // both have read the same dead holder
      const at = await b2.advance(k);
      await b.finish("boot");
      await b2.finish("boot");
      assertOneHolder(s, [b, b2], `B ran in full after ${k} of B2's takeover calls`);
      assert.equal(b.holding || b2.holding, true, `liveness (k=${k}): a dead holder's lock is taken over by one of them`);
      return at.type === "op";
    } finally {
      await releaseAll([b, b2]);
    }
  });
});

test("[PROOF:GATE-LOCK-STALE-MUTEX] K13 stale takeover mutex — a mutex left by a dead process is never removed automatically: the boot is STATE_TAKEOVER_STALE and nothing is touched, even with two takers interleaved", { timeout: 120_000 }, async () => {
  // One boot: the dead holder's lock and the dead mutex are both left exactly as they were.
  const s = stage();
  writeFileSync(s.lockPath, `${DEAD_PID}\n`, { mode: 0o600 });
  writeFileSync(`${s.lockPath}.takeover`, `${DEAD_PID}\n`, { mode: 0o600 });
  const [one] = actors(s, ["ONE"]) as [LockActor];
  try {
    await one.start("boot");
    const r = await one.finish("boot");
    assert.equal(one.holding, false, "consequence: no boot proceeds past a stale takeover mutex");
    assert.equal(readFileSync(s.lockPath, "utf8"), `${DEAD_PID}\n`, "consequence: the dead holder's lock is untouched");
    assert.equal(readFileSync(`${s.lockPath}.takeover`, "utf8"), `${DEAD_PID}\n`, "consequence: the stale mutex is not removed automatically");
    assert.equal(r.code, "STATE_TAKEOVER_STALE");
  } finally {
    await releaseAll([one]);
  }
  // Two takers interleaved at every point: still never two holders.
  await everyCutIn(async (k) => {
    const t = stage();
    writeFileSync(t.lockPath, `${DEAD_PID}\n`, { mode: 0o600 });
    writeFileSync(`${t.lockPath}.takeover`, `${DEAD_PID}\n`, { mode: 0o600 });
    const [b, b2] = actors(t, ["B", "B2"]) as [LockActor, LockActor];
    try {
      await b.start("boot");
      await b.advance(2);
      await b2.start("boot");
      await b2.advance(2);
      const at = await b2.advance(k);
      await b.finish("boot");
      await b2.finish("boot");
      assertOneHolder(t, [b, b2], `stale mutex, B ran in full after ${k} of B2's calls`);
      return at.type === "op";
    } finally {
      await releaseAll([b, b2]);
    }
  });
});

test("K13 live takeover mutex — while another boot is taking the dead holder's lock over, a boot is STATE_LOCKED and touches nothing", { timeout: 60_000 }, async () => {
  const s = stage();
  writeFileSync(s.lockPath, `${DEAD_PID}\n`, { mode: 0o600 });
  writeFileSync(`${s.lockPath}.takeover`, `${process.pid}\n`, { mode: 0o600 });
  const [one] = actors(s, ["ONE"]) as [LockActor];
  try {
    await one.start("boot");
    const r = await one.finish("boot");
    assert.equal(one.holding, false, "consequence: no boot proceeds while a live takeover is in progress");
    assert.equal(readFileSync(s.lockPath, "utf8"), `${DEAD_PID}\n`, "consequence: the dead holder's lock is untouched");
    assert.equal(readFileSync(`${s.lockPath}.takeover`, "utf8"), `${process.pid}\n`, "the live mutex is untouched");
    assert.equal(r.code, "STATE_LOCKED");
  } finally {
    await releaseAll([one]);
  }
});
