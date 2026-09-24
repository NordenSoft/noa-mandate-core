/**
 * One gate boot, run in a worker thread so a test can interleave several boots DETERMINISTICALLY over
 * the real lock code. Every filesystem call this worker makes on the roster-state lock (or on a file
 * named after it: the takeover mutex, an aside copy) first reports itself to the test and then blocks
 * until the test grants it. The patch replaces the `node:fs` functions and re-syncs the ES module
 * bindings, so `pinned-file.ts` runs unmodified. See `lock-interleave.ts` for the scheduler.
 */
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { parentPort, workerData } from "node:worker_threads";
import type { LoadPinnedTrustInput } from "../../src/trust.js";

interface ActorData {
  readonly flag: SharedArrayBuffer;
  readonly lockPath: string;
  readonly deadPid: number;
  readonly input: Omit<LoadPinnedTrustInput, "now" | "isProcessAlive">;
}
const data = workerData as ActorData;
const flag = new Int32Array(data.flag);
const port = parentPort!;

const watched = (p: unknown): p is string => typeof p === "string" && (p === data.lockPath || p.startsWith(`${data.lockPath}.`));
function gate(op: string, args: readonly unknown[]): void {
  const hit = args.slice(0, 2).find(watched);
  if (hit === undefined) return;
  port.postMessage({ type: "op", op, path: hit.slice(data.lockPath.length) || "(lock)" });
  Atomics.wait(flag, 0, 0);
  Atomics.store(flag, 0, 0);
}
const mutableFs = fs as unknown as Record<string, (...args: unknown[]) => unknown>;
for (const name of ["openSync", "unlinkSync", "renameSync", "linkSync", "lstatSync"]) {
  const original = mutableFs[name]!;
  mutableFs[name] = (...args: unknown[]) => {
    gate(name, args);
    return original(...args);
  };
}
syncBuiltinESMExports();

const { loadPinnedTrust } = await import("../../src/trust.js");
let held: { release(): void } | null = null;
port.on("message", (command: string) => {
  if (command === "boot") {
    const r = loadPinnedTrust({
      ...data.input,
      now: () => data.input.nowMs,
      // Every actor is a thread of this one process, so they share its pid: that pid is alive, and only
      // the pid written into a stale lock or mutex by the test is dead.
      isProcessAlive: (pid: number) => pid !== data.deadPid,
    });
    if (r.ok) held = r;
    port.postMessage({ type: "done", ok: r.ok, code: r.ok ? null : r.code });
  } else if (command === "release") {
    held?.release();
    held = null;
    port.postMessage({ type: "done", ok: true, code: null });
  }
});
port.postMessage({ type: "ready" });
