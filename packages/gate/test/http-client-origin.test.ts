import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { HttpGateClient } from "../src/wrapper.js";

const testKey = "test-only-gate-origin-credential";
const payload = new TextEncoder().encode("{}");

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return address.port;
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

test("HTTP client rejects invalid credential destinations before making a request", () => {
  for (const endpoint of ["invalid", "http://gate.example.test", "http://localhost:8899", "ftp://127.0.0.1",
    "https://user:pass@gate.example.test", "https://gate.example.test/api", "https://gate.example.test/?query=1",
    "https://gate.example.test/#fragment", "https://gate.example.test/?", "https://gate.example.test/#"]) {
    assert.throws(() => new HttpGateClient(endpoint, testKey), /GATE_ENDPOINT_INVALID/);
  }
});

test("HTTP client normalizes trusted HTTPS and literal loopback origins", async (t) => {
  const observed: string[] = [];
  t.mock.method(globalThis, "fetch", async (input: Parameters<typeof fetch>[0]) => {
    observed.push(String(input));
    return new Response("{}", { status: 200 });
  });
  for (const [input, origin] of [
    ["HTTPS://GATE.EXAMPLE.TEST:443/", "https://gate.example.test"],
    ["http://127.0.0.1:8899/", "http://127.0.0.1:8899"],
    ["http://[::1]:8899/", "http://[::1]:8899"],
  ] as const) {
    await new HttpGateClient(input, testKey).reserve("test-grant");
    assert.equal(observed.at(-1), `${origin}/v1/grants/test-grant/reserve`);
  }
});

test("all four HTTP client operations refuse actual redirects", async () => {
  let initial = 0;
  let redirected = 0;
  const server = createServer((request, response) => {
    if (request.url === "/redirect-target") {
      redirected++;
      response.writeHead(200).end("{}");
    } else {
      initial++;
      response.writeHead(307, { location: "/redirect-target" }).end();
    }
  });
  const port = await listen(server);
  try {
    const client = new HttpGateClient(`http://127.0.0.1:${port}`, testKey);
    for (const invoke of [() => client.createHold("test-idem", payload), () => client.wait("test-hold", 1000),
      () => client.reserve("test-grant"), () => client.report("test-grant", payload)]) {
      await assert.rejects(invoke);
    }
    assert.equal(initial, 4);
    assert.equal(redirected, 0);
  } finally {
    await close(server);
  }
});

function cli(args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL("../src/cli.js", import.meta.url)), "hold-and-run", ...args],
      { env: { ...process.env, NOA_GATE_KEY: testKey, NOA_GATE_URL: undefined, ...env }, stdio: ["ignore", "ignore", "pipe"], timeout: 5000 });
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (text: string) => { stderr += text; });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stderr }));
  });
}

test("CLI refuses an argument origin paired with an environment-only credential", async () => {
  const result = await cli(["--url", "https://gate.example.test", "--", "test-command"], {});
  assert.equal(result.code, 2);
  assert.match(result.stderr, /GATE_CREDENTIAL_SOURCE_MISMATCH/);
  assert.ok(!result.stderr.includes(testKey));
});

test("CLI refuses an environment origin paired with an argument-only credential", async () => {
  let requests = 0;
  const server = createServer((_request, response) => {
    requests++;
    response.writeHead(401, { "content-type": "application/json" }).end("{}");
  });
  const port = await listen(server);
  try {
    const result = await cli(["--key", testKey, "--", "test-command"], { NOA_GATE_URL: `http://127.0.0.1:${port}` });
    assert.equal(result.code, 2, result.stderr);
    assert.match(result.stderr, /GATE_CREDENTIAL_SOURCE_MISMATCH/);
    assert.ok(!result.stderr.includes(testKey));
    assert.equal(requests, 0);
  } finally {
    await close(server);
  }
});

test("CLI uses the trusted environment pair and keeps command arguments after -- separate", async () => {
  let requests = 0;
  const server = createServer((request, response) => {
    requests++;
    assert.equal(request.url, "/v1/holds");
    assert.equal(request.headers.authorization, `Bearer ${testKey}`);
    response.writeHead(401, { "content-type": "application/json" }).end("{}");
  });
  const port = await listen(server);
  try {
    const endpoint = `http://127.0.0.1:${port}`;
    const envPair = await cli(["--", "test-command", "--url", "https://command-argument.example.test"], { NOA_GATE_URL: endpoint });
    assert.equal(envPair.code, 1, envPair.stderr);
    assert.ok(!envPair.stderr.includes("GATE_CREDENTIAL_SOURCE_MISMATCH"));
    const explicitPair = await cli(["--url", endpoint, "--key", testKey, "--", "test-command"], {});
    assert.equal(explicitPair.code, 1, explicitPair.stderr);
    assert.equal(requests, 2);
  } finally {
    await close(server);
  }
});
