import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { test, type TestContext } from "node:test";
import { runServe } from "../../src/serve.js";
import {
  buildRequest,
  CODE,
  frame,
  parseErrorFrame,
  parseResponse,
} from "../helpers/serve-client.js";

const doc = readFileSync(
  new URL("../../../conformance/vectors/valid-chain.json", import.meta.url),
);
const keyring = readFileSync(
  new URL("../../../conformance/vectors/keyring.json", import.meta.url),
);
const checkpoint = readFileSync(
  new URL("../../../conformance/vectors/checkpoint.json", import.meta.url),
);

type Listener = (...args: unknown[]) => void;
type Input = {
  on(event: string, listener: Listener): Input;
  pause(): Input;
};
type Output = {
  write(chunk: string | Uint8Array, ...args: unknown[]): boolean;
};

type ServeHarness = {
  data(chunk: Uint8Array): void;
  end(): void;
  done: Promise<number>;
  settled(): boolean;
  takePayloads(): Buffer[];
};

function request(id: bigint, nonceByte: number) {
  return buildRequest({
    id,
    nonce: Buffer.alloc(32, nonceByte),
    doc,
    keyring,
    checkpoint,
  });
}

function drainPayloads(chunks: Buffer[]): Buffer[] {
  const bytes = Buffer.concat(chunks.splice(0));
  const payloads: Buffer[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    assert.ok(bytes.length - offset >= 4, "captured output ended inside a frame prefix");
    const length = bytes.readUInt32BE(offset);
    const end = offset + 4 + length;
    assert.ok(end <= bytes.length, "captured output ended inside a frame payload");
    payloads.push(bytes.subarray(offset + 4, end));
    offset = end;
  }
  return payloads;
}

function assertResponse(payload: Buffer, id: bigint): void {
  const response = parseResponse(payload);
  assert.ok(response, "response payload must parse");
  assert.equal(response.id, id);
  const verdict = JSON.parse(response.verdictBytes.toString("utf8")) as { status?: unknown };
  assert.equal(verdict.status, "VALID");
}

function createHarness(t: TestContext, args: string[]): ServeHarness {
  const stdoutChunks: Buffer[] = [];
  let dataListener: ((chunk: Uint8Array) => void) | undefined;
  let endListener: (() => void) | undefined;
  let errorListener: ((error: Error) => void) | undefined;

  const input = process.stdin as unknown as Input;
  const stdout = process.stdout as unknown as Output;
  const stderr = process.stderr as unknown as Output;

  try {
  t.mock.method(input, "on", (event: string, listener: Listener) => {
    if (event === "data") dataListener = listener as (chunk: Uint8Array) => void;
    else if (event === "end") endListener = listener as () => void;
    else if (event === "error") errorListener = listener as (error: Error) => void;
    return input;
  });
  t.mock.method(input, "pause", () => input);
  t.mock.method(stdout, "write", (chunk: string | Uint8Array) => {
    stdoutChunks.push(typeof chunk === "string" ? Buffer.from(chunk) : Buffer.from(chunk));
    return true;
  });
  t.mock.method(stderr, "write", () => true);

  let isSettled = false;
  const done = runServe(args).then((code) => {
    isSettled = true;
    return code;
  });

  assert.ok(dataListener, "runServe did not register its stdin data listener");
  assert.ok(endListener, "runServe did not register its stdin end listener");
  assert.ok(errorListener, "runServe did not register its stdin error listener");
  assert.equal(drainPayloads(stdoutChunks).length, 1, "runServe must emit exactly one HELLO frame");

  return {
    data(chunk) {
      dataListener?.(chunk);
    },
    end() {
      endListener?.();
    },
    done,
    settled: () => isSettled,
    takePayloads: () => drainPayloads(stdoutChunks),
  };
  } catch (error) {
    endListener?.();
    t.mock.timers.reset();
    t.mock.restoreAll();
    throw error;
  }
}

async function disposeHarness(t: TestContext, harness: ServeHarness): Promise<void> {
  if (!harness.settled()) harness.end();
  await harness.done;
  t.mock.timers.reset();
  t.mock.restoreAll();
}

test("frame deadline is absolute across partial-prefix and partial-payload activity", { concurrency: false }, async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const harness = createHarness(t, ["--frame-timeout-ms", "100"]);
  const bytes = frame(request(1n, 1).payload);
  try {
    harness.data(bytes.subarray(0, 1));
    t.mock.timers.tick(60);
    harness.data(bytes.subarray(1, 5));
    t.mock.timers.tick(39);
    assert.equal(harness.takePayloads().length, 0);

    t.mock.timers.tick(1);
    const errors = harness.takePayloads();
    assert.equal(errors.length, 1);
    const error = parseErrorFrame(errors[0]!);
    assert.ok(error, "timeout payload must parse as an error frame");
    assert.equal(error.code, CODE.FRAME_TIMEOUT);
    await harness.done;
  } finally {
    await disposeHarness(t, harness);
  }
});

test("a completed frame and batched partial successor receive distinct deadlines", { concurrency: false }, async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const harness = createHarness(t, ["--frame-timeout-ms", "100"]);
  const first = frame(request(1n, 1).payload);
  const second = frame(request(2n, 2).payload);
  try {
    harness.data(first.subarray(0, 1));
    t.mock.timers.tick(80);
    harness.data(Buffer.concat([first.subarray(1), second.subarray(0, 1)]));

    const responses = harness.takePayloads();
    assert.equal(responses.length, 1);
    assertResponse(responses[0]!, 1n);

    t.mock.timers.tick(99);
    assert.equal(harness.takePayloads().length, 0);
    t.mock.timers.tick(1);
    const errors = harness.takePayloads();
    assert.equal(errors.length, 1);
    const error = parseErrorFrame(errors[0]!);
    assert.ok(error, "timeout payload must parse as an error frame");
    assert.equal(error.code, CODE.FRAME_TIMEOUT);
    await harness.done;
  } finally {
    await disposeHarness(t, harness);
  }
});

test("completing a frame clears its deadline without creating an idle timeout", { concurrency: false }, async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const harness = createHarness(t, ["--frame-timeout-ms", "100"]);
  const bytes = frame(request(1n, 1).payload);
  try {
    harness.data(bytes.subarray(0, 1));
    t.mock.timers.tick(80);
    harness.data(bytes.subarray(1));
    const responses = harness.takePayloads();
    assert.equal(responses.length, 1);
    assertResponse(responses[0]!, 1n);

    t.mock.timers.tick(1_000);
    assert.equal(harness.takePayloads().length, 0);
    harness.end();
    assert.equal(await harness.done, 0);
  } finally {
    await disposeHarness(t, harness);
  }
});

test("the maximum representable timer delay remains valid", { concurrency: false }, async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const harness = createHarness(t, ["--frame-timeout-ms", "2147483647"]);
  try {
    harness.data(frame(request(1n, 1).payload));
    const responses = harness.takePayloads();
    assert.equal(responses.length, 1);
    assertResponse(responses[0]!, 1n);
    harness.end();
    assert.equal(await harness.done, 0);
  } finally {
    await disposeHarness(t, harness);
  }
});

test("invalid frame-timeout values are refused before HELLO", { concurrency: false }, async (t) => {
  const stdoutChunks: Buffer[] = [];
  const stderrChunks: Buffer[] = [];
  const stdout = process.stdout as unknown as Output;
  const stderr = process.stderr as unknown as Output;
  t.mock.method(stdout, "write", (chunk: string | Uint8Array) => {
    stdoutChunks.push(typeof chunk === "string" ? Buffer.from(chunk) : Buffer.from(chunk));
    return true;
  });
  t.mock.method(stderr, "write", (chunk: string | Uint8Array) => {
    stderrChunks.push(typeof chunk === "string" ? Buffer.from(chunk) : Buffer.from(chunk));
    return true;
  });

  try {
    const invalid = [
      ["--frame-timeout-ms", "2147483648"],
      ["--frame-timeout-ms", Number.MAX_SAFE_INTEGER.toString()],
      ["--frame-timeout-ms"],
      ["--frame-timeout-ms", "0"],
      ["--frame-timeout-ms", "1.5"],
    ];
    for (const args of invalid) {
      stdoutChunks.length = 0;
      stderrChunks.length = 0;
      assert.equal(await runServe(args), 4, JSON.stringify(args));
      assert.equal(Buffer.concat(stdoutChunks).length, 0, `${JSON.stringify(args)} emitted HELLO`);
      assert.match(Buffer.concat(stderrChunks).toString("utf8"), /frame-timeout-ms/i);
    }
  } finally {
    t.mock.restoreAll();
  }
});
