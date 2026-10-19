import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { MAINNET } from "../src/config.ts";
import { Ctx } from "../src/context.ts";
import { renderMarkdown } from "../src/docs.ts";
import { createLocalStdioMcpServer, makeServer } from "../src/server.ts";

const CHAIN_TOOL_NAMES = [
  "get_account",
  "get_smart_account",
  "get_portfolio",
  "get_account_activity",
  "get_transactions",
  "get_transfers",
  "list_assets",
  "get_asset",
  "get_swap_quote",
  "get_gas_payment_options",
  "get_network_status",
  "get_transaction",
  "get_user_operation",
  "get_block",
  "search",
  "build_transfer",
  "build_swap",
  "broadcast_user_operation",
  "build_transaction",
  "get_bridge_routes",
  "build_bridge_transfer",
  "build_bridge_transfer_out",
  "get_bridge_status",
  "broadcast_transaction",
];

const WALLET_TOOL_NAMES = [
  "create_agent_wallet",
  "get_agent_wallet",
  "send_transfer",
  "send_swap",
  "get_agent_operation",
];

function context() {
  return new Ctx(MAINNET);
}

async function registeredToolNames(bundle) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "capability-test", version: "0.0.0" });
  await bundle.server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    return (await client.listTools()).tools.map((tool) => tool.name);
  } finally {
    await client.close();
    await bundle.server.close();
  }
}

test("local stdio registers exactly five local wallet tools without accessing wallet storage", async () => {
  const bundle = await createLocalStdioMcpServer(context());

  assert.deepEqual(bundle.capabilities, { publicTools: true, walletTools: true });
  assert.deepEqual(bundle.catalog.map((tool) => tool.name), [...CHAIN_TOOL_NAMES, ...WALLET_TOOL_NAMES]);
  assert.deepEqual(await registeredToolNames(bundle), [...CHAIN_TOOL_NAMES, ...WALLET_TOOL_NAMES]);

  const docs = renderMarkdown(MAINNET, bundle.catalog);
  assert.match(docs, /local MCP server/);
  assert.match(docs, /administration passphrase never enters MCP/);
  assert.match(docs, /npm install --global --ignore-scripts incentiv-mcp/);
  assert.match(docs, /"command": "incentiv-mcp"/);
  assert.doesNotMatch(docs, /"type": "http"/);
});

test("the server requires explicit wallet dependencies", () => {
  assert.throws(() => makeServer(context(), undefined), /requires explicit wallet dependencies/);
});

test("wallet tool schemas reject secrets/arbitrary calls and send annotations describe retries", async () => {
  const { registerWalletTools } = await import("../src/wallet/tools.ts");
  let calls = 0;
  const wallet = { send: async () => { calls++; return {}; } };
  const bundle = makeServer(context(), server => registerWalletTools(server, wallet));
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "wallet-boundary-test", version: "1" });
  await bundle.server.connect(serverTransport); await client.connect(clientTransport);
  try {
    const { tools } = await client.listTools();
    for (const name of ["send_transfer", "send_swap"]) assert.deepEqual(tools.find(t => t.name === name).annotations, { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true });
    const response = await client.callTool({ name: "send_transfer", arguments: { request_id: "00000000-0000-4000-8000-000000000000", token: "CENT", to: "0x0000000000000000000000000000000000000001", amount: "1", private_key: "SECRET_CANARY", calls: [] } });
    assert.equal(response.isError, true); assert.equal(calls, 0); assert.ok(!JSON.stringify(response).includes("SECRET_CANARY"));
  } finally { await client.close(); await bundle.server.close(); }
});
