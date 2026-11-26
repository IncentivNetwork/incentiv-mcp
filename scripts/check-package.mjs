import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { installTestPackage } from "./install-test-package.mjs";
const npm = process.env.npm_execpath;
assert.ok(npm, "Run npm run check:package");
const [packed] = JSON.parse(execFileSync(process.execPath, [npm, "pack", "--dry-run", "--ignore-scripts", "--json"], { encoding: "utf8" }));
const files = new Set(packed.files.map(f => f.path));
for (const path of ["dist/index.js", "dist/setup.js", "dist/setup-policy.js", "dist/setup-client.js", "dist/onboarding-docs.js", "dist/wallet/windows-permissions.ps1", "dist/wallet/capabilities.js", "dist/wallet/recovery.js", "npm-shrinkwrap.json", "docs/wallet-usage.md", "docs/wallet-policy.example.json", "docs/agent-registry.md", "dist/agent-registry.js", "docs/x402.md", "dist/x402/tools.js"]) assert.ok(files.has(path), `Missing ${path}`);
assert.ok([...files].every(path => !path.startsWith("test/") && !path.startsWith(".cache/") && !path.endsWith("master.key")));
for (const path of ["dist/account-upgrade.js", "dist/wallet/implementation.js"]) assert.ok(files.has(path), `Missing ${path}`);
const pkg = JSON.parse(await readFile("package.json", "utf8")), lock = JSON.parse(await readFile("npm-shrinkwrap.json", "utf8"));
assert.equal(pkg.version, lock.version);
for (const [name, version] of Object.entries(pkg.dependencies)) assert.equal(version, lock.packages[`node_modules/${name}`].version);
for (const name of ["preinstall", "install", "postinstall"]) assert.equal(pkg.scripts[name], undefined);

const directory = await mkdtemp(join(tmpdir(), "incentiv-package-"));
try {
  const { dist } = await installTestPackage(process.cwd(), directory);
  const client = new Client({ name: "incentiv-package-smoke", version: "1.0.0" });
  // Use the installed stdio server constructor without the live chain startup probe.
  const child = `
    import assert from "node:assert/strict";
    import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
    import { MAINNET } from "./node_modules/incentiv-mcp/dist/config.js";
    import { Ctx } from "./node_modules/incentiv-mcp/dist/context.js";
    import { createLocalStdioMcpServer } from "./node_modules/incentiv-mcp/dist/server.js";
    import { incentivX402, x402Config } from "./node_modules/incentiv-mcp/dist/x402/protocol.js";
    const decoder = await incentivX402();
    assert.equal(typeof decoder.decodePaymentOp, "function");
    assert.throws(() => decoder.decodePaymentOp({ callData: "0x" }, x402Config(MAINNET)), /callData is not an account call/);
    const { server } = await createLocalStdioMcpServer(new Ctx(MAINNET));
    await server.connect(new StdioServerTransport());
  `;
  const transport = new StdioClientTransport({
    command: process.execPath, args: ["--input-type=module", "-e", child], cwd: directory, stderr: "inherit",
  });
  try {
    const version = execFileSync(process.execPath, [join(dist, "index.js"), "--version"], { encoding: "utf8" }).trim();
    assert.equal(version, pkg.version);
    await client.connect(transport);
    const { tools } = await client.listTools();
    for (const name of ["get_x402_payment_requirements", "pay_x402_resource"]) {
      assert.ok(tools.some(tool => tool.name === name), `Missing installed MCP tool ${name}`);
    }
  } finally { await client.close(); }
} finally { await rm(directory, { recursive: true, force: true }); }
console.log(`Package verified: ${files.size} files, pinned runtime dependencies, installed MCP stdio and x402 decoder`);
