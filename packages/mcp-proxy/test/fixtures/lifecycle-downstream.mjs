#!/usr/bin/env node
/**
 * lifecycle-downstream.mjs — a real stdio MCP tool server for test/lifecycle.test.mjs. It speaks MCP
 * through the official SDK exactly like a user's own server; the switches below only change how it
 * behaves when it is asked to stop. They are read from the command line, because the proxy starts its
 * downstream with the SDK's filtered environment.
 *
 *   --pid-file <path>   write this process's pid to <path> once it is serving, so the test can find
 *                       the process the proxy started.
 *   --stay-alive        keep running after stdin closes (a timer holds the event loop), as many real
 *                       servers do. Without it, closing the child's stdin alone would end it, and a
 *                       test could not tell "the proxy stopped its child" from "the child left".
 *   --ignore-sigterm    ignore SIGTERM, so only SIGKILL stops it.
 *   --never-answer      never start the MCP server: the proxy's initialize request is read by no one.
 *   --tag <value>       not read; it marks this process's command line so a test can confirm a pid
 *                       is still its own process before it signals it.
 */
import { writeFileSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const argv = process.argv.slice(2);
const has = (flag) => argv.includes(flag);
const valueOf = (flag) => {
  const i = argv.indexOf(flag);
  return i === -1 ? undefined : argv[i + 1];
};

if (has("--ignore-sigterm")) process.on("SIGTERM", () => {});
if (has("--stay-alive") || has("--never-answer")) setInterval(() => {}, 1000);

if (!has("--never-answer")) {
  const server = new Server({ name: "lifecycle-downstream", version: "1.0.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: "echo", description: "Echo back the given text.", inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } }],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => ({
    content: [{ type: "text", text: String(request.params.arguments?.text ?? "") }],
  }));
  await server.connect(new StdioServerTransport());
}

const pidFile = valueOf("--pid-file");
if (pidFile) writeFileSync(pidFile, String(process.pid), "utf8");
