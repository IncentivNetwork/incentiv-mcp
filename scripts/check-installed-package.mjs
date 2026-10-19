import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

// Public reads and tools/list only. Never create, unlock or use a wallet here.
const directory = resolve(process.argv[2]);
const pkg = JSON.parse(await readFile(join(directory, "package.json"), "utf8"));
const expected = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
assert.equal(pkg.name, expected.name); assert.equal(pkg.version, expected.version);
const entry = join(directory, "dist", "index.js");
assert.equal(execFileSync(process.execPath, [entry, "--version"], { encoding: "utf8" }).trim(), expected.version);
assert.match(execFileSync(process.execPath, [entry, "--help"], { encoding: "utf8" }), /Guided wallet setup/);
const env = Object.fromEntries(Object.entries(process.env).filter(([key, value]) => value !== undefined && !key.startsWith("INCENTIV_")));
const transport = new StdioClientTransport({ command: process.execPath, args: ["--use-system-ca", entry], env, stderr: "ignore" });
const client = new Client({ name: "incentiv-installed-package-check", version: "1" });
let timer;
try {
  await Promise.race([client.connect(transport), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Installed MCP startup timed out")), 60_000); })]);
  clearTimeout(timer);
  const { tools } = await client.listTools();
  assert.equal(tools.length, 29);
  for (const name of ["get_network_status", "get_portfolio", "create_agent_wallet", "get_agent_wallet", "send_transfer", "send_swap", "get_agent_operation"]) assert.ok(tools.some(tool => tool.name === name), `Missing ${name}`);
  console.log(`Installed incentiv-mcp@${pkg.version}: version, help and 29-tool catalog verified; no wallet operation invoked.`);
} finally { clearTimeout(timer); await client.close(); await transport.close(); }
