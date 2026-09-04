import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** Versioned machine contracts shared by the proof reporter, parser and knockout observer. */
export const PROOF_EVENT_PROTOCOL = "noa-proof-runner/1";
export const PROOF_EVENT_TRANSPORT_PROTOCOL = "noa-proof-transport/1";
export const PROOF_EVENT_REPORTER_ID = "noa-proof-reporter/1";
export const PROOF_EVENT_SOCKET_ENV = "NOA_KNOCKOUT_TEST_EVENT_SOCKET";
export const PROOF_EVENT_TOKEN_ENV = "NOA_KNOCKOUT_TEST_EVENT_TOKEN";
const REPORTER_SOURCE_PATH = fileURLToPath(new URL("./proof-event-reporter.mjs", import.meta.url));
// Seal the reporter bytes while the trusted parent module loads, before any subject-controlled
// build or preparation step can run. The child imports this immutable data URL, never the later
// contents of a writable repository path.
export const PROOF_EVENT_REPORTER = `data:text/javascript;base64,${
  Buffer.from(readFileSync(REPORTER_SOURCE_PATH)).toString("base64")
}`;

/** Exact NODE_OPTIONS spelling owned by the knockout observer. */
export const proofEventReporterNodeOption = () =>
  `--test-reporter=${JSON.stringify(PROOF_EVENT_REPORTER)}`;
