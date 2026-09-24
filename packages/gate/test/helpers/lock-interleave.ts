/**
 * A deterministic scheduler for gate boots running in worker threads (`lock-actor.ts`). Each actor
 * stops before every filesystem call on the roster-state lock; the test decides which actor moves
 * next, one call at a time, so an interleaving that a real race produces only rarely is reproduced
 * exactly, over the real lock code, on every run.
 */
import { Worker } from "node:worker_threads";
import type { LoadPinnedTrustInput } from "../../src/trust.js";

export type ActorDone = { readonly type: "done"; readonly ok: boolean; readonly code: string | null };
export type ActorEvent = { readonly type: "op"; readonly op: string; readonly path: string } | ActorDone;

export class LockActor {
  private readonly flag = new Int32Array(new SharedArrayBuffer(4));
  private readonly worker: Worker;
  private readonly queue: ActorEvent[] = [];
  private waiting: ((e: ActorEvent) => void) | null = null;
  private pending: ActorEvent | null = null;
  private readonly ready: Promise<void>;
  /** True between a successful boot and its release. */
  holding = false;

  constructor(readonly name: string, lockPath: string, deadPid: number, input: Omit<LoadPinnedTrustInput, "now" | "isProcessAlive">) {
    this.worker = new Worker(new URL("./lock-actor.js", import.meta.url), {
      workerData: { flag: this.flag.buffer, lockPath, deadPid, input },
    });
    let resolveReady!: () => void;
    this.ready = new Promise((r) => { resolveReady = r; });
    this.worker.on("message", (m: ActorEvent | { type: "ready" }) => {
      if (m.type === "ready") return resolveReady();
      if (this.waiting !== null) {
        const w = this.waiting;
        this.waiting = null;
        w(m);
      } else {
        this.queue.push(m);
      }
    });
    this.worker.on("error", (e) => { throw e; });
  }

  private next(): Promise<ActorEvent> {
    const queued = this.queue.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    return new Promise((r) => { this.waiting = r; });
  }

  /** The actor's current event: the filesystem call it is waiting to make, or its finished result. */
  async peek(): Promise<ActorEvent> {
    if (this.pending === null) this.pending = await this.next();
    return this.pending;
  }

  /** Let the pending filesystem call go ahead. */
  grant(): void {
    this.pending = null;
    Atomics.store(this.flag, 0, 1);
    Atomics.notify(this.flag, 0, 1);
  }

  async start(command: "boot" | "release"): Promise<void> {
    await this.ready;
    this.pending = null;
    this.worker.postMessage(command);
  }

  /** Grant up to `n` filesystem calls; returns the event the actor then stands at. */
  async advance(n: number): Promise<ActorEvent> {
    for (let i = 0; i < n; i++) {
      const e = await this.peek();
      if (e.type === "done") return e;
      this.grant();
    }
    return this.peek();
  }

  /** Run the current command to its end. */
  async finish(command: "boot" | "release"): Promise<ActorDone> {
    for (;;) {
      const e = await this.peek();
      if (e.type === "done") {
        this.pending = null;
        this.holding = command === "boot" ? e.ok : false;
        return e;
      }
      this.grant();
    }
  }

  async stop(): Promise<void> {
    await this.worker.terminate();
  }
}
