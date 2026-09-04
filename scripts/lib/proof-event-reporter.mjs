/**
 * Machine contract for proof-bearing `node:test` files.
 *
 * Built-in reporter text is presentation output, not evidence. This reporter consumes Node's
 * TestsStream and emits only versioned JSON records created from runner-owned events. Test stdout
 * and stderr are deliberately ignored: repository code under test must not be able to print a
 * line that the proof resolver mistakes for a passing control.
 */
import { once } from "node:events";
import net from "node:net";
import path from "node:path";

export const PROOF_EVENT_PROTOCOL = "noa-proof-runner/1";
const PROOF_EVENT_TRANSPORT_PROTOCOL = "noa-proof-transport/1";
const PROOF_EVENT_REPORTER_ID = "noa-proof-reporter/1";
const PROOF_EVENT_SOCKET_ENV = "NOA_KNOCKOUT_TEST_EVENT_SOCKET";
const PROOF_EVENT_TOKEN_ENV = "NOA_KNOCKOUT_TEST_EVENT_TOKEN";
// When loaded from the parent-sealed data URL this is the immutable reporter identity. Keeping the
// reporter self-contained avoids resolving any repository module after subject preparation runs.
const PROOF_EVENT_REPORTER = import.meta.url;
const proofEventReporterNodeOption = () =>
  `--test-reporter=${JSON.stringify(PROOF_EVENT_REPORTER)}`;

const TOKEN_PATTERN = /^[0-9a-f]{64}$/;
const MAX_ACK_BYTES = 1024;

function removeOwnNodeOption() {
  const reporterOption = proofEventReporterNodeOption();
  const inherited = process.env.NODE_OPTIONS ?? "";
  if (inherited !== reporterOption && !inherited.endsWith(` ${reporterOption}`)) {
    throw new Error("knockout proof transport is present without its exact controlled reporter option");
  }
  const remaining = inherited.slice(0, inherited.length - reporterOption.length).trimEnd();
  if (remaining.length === 0) delete process.env.NODE_OPTIONS;
  else process.env.NODE_OPTIONS = remaining;
}

function readAcknowledgement(socket) {
  return new Promise((resolve, reject) => {
    let buffered = Buffer.alloc(0);
    const cleanup = () => {
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
    };
    const fail = (error) => { cleanup(); reject(error); };
    const onError = (error) => fail(error);
    const onClose = () => fail(new Error("proof transport closed before acknowledgement"));
    const onData = (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      if (buffered.length > MAX_ACK_BYTES) {
        fail(new Error("proof transport acknowledgement exceeded its bound"));
        return;
      }
      const newline = buffered.indexOf(0x0a);
      if (newline < 0) return;
      if (newline !== buffered.length - 1) {
        fail(new Error("proof transport acknowledgement carried trailing bytes"));
        return;
      }
      cleanup();
      resolve(buffered.subarray(0, newline).toString("utf8"));
    };
    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
  });
}

async function connectProtectedTransport() {
  const socketPath = process.env[PROOF_EVENT_SOCKET_ENV];
  const token = process.env[PROOF_EVENT_TOKEN_ENV];
  if (socketPath === undefined && token === undefined) return null;
  if (
    typeof socketPath !== "string" || socketPath.length === 0 || !path.isAbsolute(socketPath) ||
    path.basename(socketPath) !== "events.sock"
  ) {
    throw new Error(`${PROOF_EVENT_SOCKET_ENV} does not name an absolute controlled socket`);
  }
  if (typeof token !== "string" || !TOKEN_PATTERN.test(token)) {
    throw new Error(`${PROOF_EVENT_TOKEN_ENV} is not a 256-bit lowercase hexadecimal token`);
  }

  // Consume the capability before Node starts test-file workers. Even if a Node release has
  // already copied the environment, the observer unlinks the rendezvous pathname before it
  // acknowledges this connection; only this held socket remains evidence-bearing.
  removeOwnNodeOption();
  delete process.env[PROOF_EVENT_SOCKET_ENV];
  delete process.env[PROOF_EVENT_TOKEN_ENV];

  const socket = net.createConnection({ path: socketPath });
  await once(socket, "connect");
  const acknowledgement = readAcknowledgement(socket);
  const hello = `${JSON.stringify({
    protocol: PROOF_EVENT_TRANSPORT_PROTOCOL,
    token,
    reporter: PROOF_EVENT_REPORTER_ID,
  })}\n`;
  if (!socket.write(hello)) await once(socket, "drain");
  const line = await acknowledgement;
  let value;
  try { value = JSON.parse(line); }
  catch { throw new Error("proof transport acknowledgement is not JSON"); }
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    value.protocol !== PROOF_EVENT_TRANSPORT_PROTOCOL || value.accepted !== true
  ) {
    throw new Error("proof transport acknowledgement is not the expected acceptance record");
  }
  return socket;
}

// Establish the parent-owned channel while the reporter module is loading, before consuming the
// TestsStream. Test-file workers never receive this connected descriptor.
const protectedTransport = await connectProtectedTransport();

const record = (event, fields = {}) => `${JSON.stringify({
  protocol: PROOF_EVENT_PROTOCOL,
  event,
  ...fields,
})}\n`;

const isMarked = (value) => value !== undefined && value !== false;
const stringOrNull = (value) => typeof value === "string" ? value : null;
const integerOrNull = (value) => Number.isInteger(value) && value > 0 ? value : null;
const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

async function emit(line) {
  if (protectedTransport === null) return false;
  if (!protectedTransport.write(line)) await once(protectedTransport, "drain");
  return true;
}

export default async function* proofEventReporter(source) {
  try {
    for await (const { type, data = {} } of source) {
      let line = null;
      if (type === "test:pass" || type === "test:fail") {
        const error = data.details?.error;
        line = record(type === "test:pass" ? "pass" : "fail", {
          name: stringOrNull(data.name),
          skipped: isMarked(data.skip),
          todo: isMarked(data.todo),
          suite: data.details?.type === "suite",
          // Node's file-wrapper failure has exitCode+signal and no authored test body. It is a
          // setup/build failure, not a detector failure, even though TestsStream calls it a test.
          fileFailure: type === "test:fail" && error?.code === "ERR_TEST_FAILURE" &&
            hasOwn(error, "exitCode") && hasOwn(error, "signal"),
          file: stringOrNull(data.file),
          line: integerOrNull(data.line),
          column: integerOrNull(data.column),
          failureType: stringOrNull(error?.failureType),
          message: stringOrNull(error?.message),
        });
      } else if (type === "test:plan" && data.nesting === 0) {
        // A single top-level plan terminates a one-file run. It proves that the reporter stream
        // completed; it does NOT prove that an authored test registered or passed.
        line = record("plan", { count: data.count });
      }
      if (line === null) continue;
      if (!await emit(line)) yield line;
    }
  } finally {
    if (protectedTransport !== null) protectedTransport.end();
  }
}
