import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";
import { encodeAbiParameters, keccak256, toHex, decodeFunctionData, parseAbi } from "viem";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { MAINNET, canonicalJson, configurationId, loadConfig, parseConfig, localContractPins, remoteContractPins } from "../src/config.ts";
import { assertWalletNetwork, deriveSmartAccount, networkStatusFields, verifyNetwork, walletDirectory } from "../src/network.ts";
import { Ctx } from "../src/context.ts";
import { makeServer, createLocalStdioMcpServer } from "../src/server.ts";
import { renderHtml, renderMarkdown } from "../src/docs.ts";
import { findRoute, getBridgeConfig, remoteClient, buildInboundBridge, buildOutboundBridge } from "../src/bridge.ts";
import { getPaymasterConfig } from "../src/userop.ts";
import { accountAbi } from "../src/abi.ts";

function identify(cfg) {
  cfg.identity.networkId = configurationId(cfg.identity, "networkId");
  cfg.manifest.networkId = cfg.identity.networkId;
  cfg.manifest.manifestId = configurationId(cfg.manifest, "manifestId");
  return cfg;
}

function fixture() {
  const cfg = structuredClone(MAINNET);
  for (const pin of [...localContractPins(cfg), ...Object.keys(cfg.manifest.bridge.remoteChains).flatMap((chain) => remoteContractPins(cfg, chain))]) {
    pin.codeHash = keccak256("0x60006000");
  }
  cfg.endpoints.rpcUrls = ["https://rpc-a.example.test", "https://rpc-b.example.test"];
  for (const [name, endpoints] of Object.entries(cfg.endpoints.remoteChains)) endpoints.rpcUrls = [`https://${name}.example.test`];
  return parseConfig(identify(cfg));
}

const encoded = (address) => encodeAbiParameters([{ type: "address" }], [address]);
function mockedRpc(cfg, calls = []) {
  return async (url, method, params) => {
    calls.push({ url, method, params });
    const remote = Object.entries(cfg.endpoints.remoteChains).find(([, e]) => e.rpcUrls.includes(url));
    if (method === "eth_chainId") return toHex(remote ? cfg.manifest.bridge.remoteChains[remote[0]].chainId : cfg.identity.chainId);
    if (method === "eth_getBlockByNumber") return { hash: cfg.identity.genesisHash };
    if (method === "eth_blockNumber") return "0x123";
    if (method === "eth_getCode") return "0x60006000";
    if (method === "eth_call") {
      if (params[0].to === cfg.identity.accountBeacon.address) return encoded(cfg.identity.accountImplementation.address);
      if (params[0].data.length === 10) return encoded(cfg.identity.accountBeacon.address);
      return encoded(deriveSmartAccount(cfg, "0x0000000000000000000000000000000000000001"));
    }
    throw new Error(`Unexpected request: ${method}`);
  };
}

test("canonical IDs use stable RFC 8785 serialization and reject non-JSON input", () => {
  assert.equal(canonicalJson({ z: -0, a: [1e30, 0.002, "\n"] }), '{"a":[1e+30,0.002,"\\n"],"z":0}');
  assert.equal(canonicalJson({ "\u20ac": 1, "\r": 2, "1": 3, "\ud83d\ude00": 4, "\ufb33": 5 }), '{"\\r":2,"1":3,"€":1,"😀":4,"דּ":5}');
  for (const value of [NaN, Infinity, undefined, 1n, "\ud800", { a: undefined }, Array(1)]) assert.throws(() => canonicalJson(value));
  assert.equal(configurationId({ ...MAINNET.identity }, "networkId"), MAINNET.identity.networkId);
  assert.equal(configurationId(Object.fromEntries(Object.entries(MAINNET.manifest).reverse()), "manifestId"), MAINNET.manifest.manifestId);
});

test("complete custom configuration loads; endpoint changes preserve wallet identity", () => {
  const cfg = structuredClone(MAINNET);
  const directory = mkdtempSync(join(tmpdir(), "incentiv-network-test-"));
  try {
    const file = join(directory, "network.json");
    writeFileSync(file, JSON.stringify(cfg));
    const custom = loadConfig({ INCENTIV_NETWORK_CONFIG: file, INCENTIV_RPC_URL: "https://mirror.example.test" });
    assert.deepEqual(custom.identity, cfg.identity);
    assert.equal(custom.endpoints.rpcUrls[0], "https://mirror.example.test/");
    assertWalletNetwork(custom, { networkIdentity: cfg.identity, approvedCapabilityManifestId: cfg.manifest.manifestId });
    assert.equal(walletDirectory(), join(homedir(), ".incentiv-mcp", "wallet"));
    assert.equal(loadConfig({}).endpoints.rpcUrls[0], MAINNET.endpoints.rpcUrls[0]);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("partial overrides, incomplete files, stale IDs and inconsistent capabilities are rejected", () => {
  for (const name of ["CHAIN_ID", "ACCOUNT_FACTORY", "ENTRY_POINT", "PAYMASTER", "QUOTER"]) {
    assert.throws(() => loadConfig({ [`INCENTIV_${name}`]: "24101" }), /Partial network/);
  }
  assert.throws(() => loadConfig({ INCENTIV_NETWORK_CONFIG: "relative.json" }), /absolute path/);
  const mutations = [
    (c) => { delete c.identity.genesisHash; },
    (c) => { c.identity.chainId = 1; },
    (c) => { c.manifest.contracts.swapRouter.codeHash = "0x12"; },
    (c) => { c.endpoints.rpcUrls = []; },
    (c) => { c.endpoints.rpcUrls = ["https://rpc.test", "https:rpc.test/"]; },
    (c) => { c.endpoints.rpcUrls = ["https://user:secret@example.test"]; },
    (c) => { c.endpoints.extra = "ignored?"; },
    (c) => { c.manifest.bridge.routes[0].symbol = "usdc"; identify(c); },
    (c) => { c.manifest.bridge.remoteChains.Base = c.manifest.bridge.remoteChains.base; identify(c); },
    (c) => { c.manifest.networkId = "0x" + "01".repeat(32); c.manifest.manifestId = configurationId(c.manifest, "manifestId"); },
    (c) => { c.accountCreationCode = "0x6000"; },
    (c) => { delete c.manifest.bridge.mailbox; identify(c); },
    (c) => { c.manifest.bridge.routes.push(c.manifest.bridge.routes[0]); identify(c); },
    (c) => { delete c.endpoints.remoteChains.base; },
    (c) => { c.manifest.canonicalTokens.WCENT.codeHash = "0x" + "01".repeat(32); identify(c); },
  ];
  for (const mutate of mutations) {
    const cfg = structuredClone(MAINNET); mutate(cfg);
    assert.throws(() => parseConfig(cfg));
  }
});

test("changed identity or unapproved capabilities cannot select a different wallet", () => {
  const binding = { networkIdentity: MAINNET.identity, approvedCapabilityManifestId: MAINNET.manifest.manifestId };
  for (const field of ["chainId", "genesisHash", "accountVersion", "accountInitCodeHash", "accountFactory", "entryPoint"]) {
    const cfg = structuredClone(MAINNET);
    cfg.identity[field] = field === "chainId" ? 1 : "changed";
    assert.throws(() => assertWalletNetwork(cfg, binding), { code: "wallet_network_mismatch" });
  }
  const cfg = structuredClone(MAINNET);
  cfg.manifest.bridge.enabled = false; identify(cfg);
  assert.deepEqual(cfg.identity, MAINNET.identity);
  assert.throws(() => assertWalletNetwork(cfg, binding), { code: "capability_manifest_unapproved" });
  assertWalletNetwork(cfg, { ...binding, approvedCapabilityManifestId: cfg.manifest.manifestId });
});

test("offline CREATE2 derivation matches a deployed mainnet account", async () => {
  const owner = "0xb6204d2a6f872e96ed273fefbe9b3190099fa4f9";
  const expected = "0x2b2D67F51C5AE1e00eAeb1EA3C8A984a3bC9c8D6";
  assert.equal(deriveSmartAccount(MAINNET, owner), expected);
  const ctx = new Ctx(MAINNET);
  ctx.client = { readContract: () => { throw new Error("RPC must not determine the funding address"); } };
  assert.equal(await ctx.deriveSmartAccount(owner), expected);
  assert.notEqual(deriveSmartAccount(MAINNET, owner, 1n), expected);
  assert.throws(() => deriveSmartAccount(MAINNET, owner, -1n));
  assert.throws(() => deriveSmartAccount(MAINNET, "0x" + "00".repeat(20)));
});

test("verification checks every RPC and every enabled pin at a fixed block", async () => {
  const cfg = fixture(), calls = [];
  await verifyNetwork(cfg, mockedRpc(cfg, calls));
  for (const url of [...cfg.endpoints.rpcUrls, ...Object.values(cfg.endpoints.remoteChains).flatMap((e) => e.rpcUrls)]) {
    assert.ok(calls.some((c) => c.url === url && c.method === "eth_chainId"));
  }
  for (const call of calls.filter((c) => c.method === "eth_getCode" || c.method === "eth_call")) assert.equal(call.params[1], "0x123");
  for (const pin of localContractPins(cfg)) assert.ok(calls.some((c) => c.method === "eth_getCode" && c.params[0] === pin.address));
});

test("local verification retains every Incentiv pin without depending on remote bridge RPCs", async () => {
  const cfg = fixture(), calls = [], good = mockedRpc(cfg, calls);
  const unavailableRemotes = async (url, method, params) => {
    if (!cfg.endpoints.rpcUrls.includes(url)) throw new Error("remote offline");
    return good(url, method, params);
  };
  await verifyNetwork(cfg, unavailableRemotes, "local");
  assert.ok(calls.every(c => cfg.endpoints.rpcUrls.includes(c.url)));
  for (const url of cfg.endpoints.rpcUrls) for (const pin of localContractPins(cfg)) assert.ok(calls.some(c => c.url === url && c.method === "eth_getCode" && c.params[0] === pin.address));
  await assert.rejects(verifyNetwork(cfg, unavailableRemotes), { code: "wallet_network_mismatch" });
  await assert.rejects(verifyNetwork(cfg, (url, method, params) => method === "eth_getCode" ? "0x6001" : unavailableRemotes(url, method, params), "local"), /Contract code mismatch/);
});

test("bridge tools and remote broadcast verify remote pins on use while local tools remain available", async t => {
  const cfg = fixture(), calls = [], good = mockedRpc(cfg, calls);
  t.mock.method(globalThis, "fetch", async (url, init) => {
    const { method, params } = JSON.parse(init.body);
    const result = await good(url, method, params);
    return Response.json({ result: url === cfg.endpoints.remoteChains.ethereum.rpcUrls[0] && method === "eth_chainId" ? "0x2" : result });
  });
  const ctx = new Ctx(cfg);
  ctx.client = { getBalance: async () => 1n, getCode: async () => "0x" };
  const bundle = makeServer(ctx, () => []);
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "bridge-scope-test", version: "1" });
  await bundle.server.connect(b); await client.connect(a);
  try {
    const address = "0x0000000000000000000000000000000000000001";
    const local = await client.callTool({ name: "get_account", arguments: { address } });
    assert.ok(!local.isError); assert.equal(calls.length, 0);
    for (const [name, input] of [
      ["get_bridge_routes", {}],
      ["build_bridge_transfer", { token: "USDC", from_chain: "ethereum", amount: "1", sender: address }],
      ["build_bridge_transfer_out", { token: "USDC", to_chain: "ethereum", amount: "1", account: address, recipient: address }],
      ["get_bridge_status", { message_id: `0x${"00".repeat(32)}`, destination: "ethereum" }],
      ["broadcast_transaction", { signed_transaction: "0x01", chain: "ethereum", wait: false }],
    ]) {
      const response = await client.callTool({ name, arguments: input });
      assert.equal(response.isError, true, name);
      assert.match(response.content[0].text, /ethereum RPC 1: Chain ID mismatch/, name);
    }
    assert.ok(calls.some(c => c.url === cfg.endpoints.remoteChains.ethereum.rpcUrls[0]));
    assert.ok(calls.every(c => c.method !== "eth_sendRawTransaction"));
  } finally { await client.close(); await bundle.server.close(); }
});

test("verification retries unavailable-block RPC errors at the identical pinned block and remains bounded", async t => {
  for (const scenario of ["recover", "exhausted", "mismatch", "invalid-params"]) await t.test(scenario, async t => {
    const cfg = fixture(), good = mockedRpc(cfg), blocks = [];
    const target = remoteContractPins(cfg, "ethereum")[0].address;
    t.mock.method(globalThis, "fetch", async (url, init) => {
      const { method, params } = JSON.parse(init.body);
      if (url === cfg.endpoints.remoteChains.ethereum.rpcUrls[0] && method === "eth_getCode" && params[0] === target) {
        blocks.push(params[1]);
        if (scenario === "invalid-params") return Response.json({ error: { code: -32602, message: "SECRET_CANARY" } });
        if (scenario === "exhausted" || blocks.length === 1) return Response.json({ error: { code: -32000, message: "header not found SECRET_CANARY" } });
        if (scenario === "mismatch") return Response.json({ result: "0x6001" });
      }
      return Response.json({ result: await good(url, method, params) });
    });
    if (scenario === "recover") await verifyNetwork(cfg);
    else await assert.rejects(verifyNetwork(cfg), error => {
      assert.doesNotMatch(error.message, /SECRET_CANARY/);
      assert.match(error.message, scenario === "mismatch" ? /Contract code mismatch/ : new RegExp(`RPC error ${scenario === "invalid-params" ? -32602 : -32000}`));
      return true;
    });
    assert.deepEqual(blocks, Array(scenario === "exhausted" ? 3 : scenario === "invalid-params" ? 1 : 2).fill("0x123"));
  });
});

test("verification retries only transient reads, remains bounded and redacts endpoint/error data", async t => {
  for (const scenario of ["http", "http-rate", "connection", "timeout", "rate-limit", "exhausted", "unauthorized", "malformed", "tls", "mismatch"]) await t.test(scenario, async t => {
    const cfg = fixture(), good = mockedRpc(cfg);
    cfg.endpoints.rpcUrls[0] = "https://rpc-a.example.test/SECRET_URL_CANARY";
    let attempts = 0;
    t.mock.method(globalThis, "fetch", async (url, init) => {
      const { method, params } = JSON.parse(init.body);
      if (url === cfg.endpoints.rpcUrls[0] && method === "eth_chainId") {
        attempts++;
        if (scenario === "exhausted" || (scenario === "http" && attempts < 3)) return new Response("SECRET_BODY_CANARY", { status: 503 });
        if (scenario === "http-rate" && attempts === 1) return new Response("SECRET_BODY_CANARY", { status: 429 });
        if (scenario === "connection" && attempts === 1) throw new TypeError("SECRET_ERROR_CANARY", { cause: { code: "ECONNRESET" } });
        if (scenario === "timeout" && attempts === 1) throw new DOMException("SECRET_ERROR_CANARY", "TimeoutError");
        if (scenario === "rate-limit" && attempts === 1) return Response.json({ error: { code: -32005, message: "SECRET_BODY_CANARY" } });
        if (scenario === "unauthorized") return new Response("SECRET_BODY_CANARY", { status: 401 });
        if (scenario === "malformed") return new Response("SECRET_BODY_CANARY");
        if (scenario === "tls") throw new TypeError("SECRET_ERROR_CANARY", { cause: { code: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" } });
        if (scenario === "mismatch") return Response.json({ result: "0x1" });
      }
      return Response.json({ result: await good(url, method, params) });
    });
    if (["http", "http-rate", "connection", "timeout", "rate-limit"].includes(scenario)) await verifyNetwork(cfg);
    else await assert.rejects(verifyNetwork(cfg), error => {
      assert.equal(error.code, "wallet_network_mismatch");
      assert.match(error.message, /local RPC 1/);
      assert.doesNotMatch(error.message, /SECRET_|example\.test/);
      if (scenario === "exhausted") assert.match(error.message, /eth_chainId unavailable \(HTTP 503; 3 attempt/);
      if (scenario === "mismatch") assert.match(error.message, /Chain ID mismatch/);
      return true;
    });
    assert.equal(attempts, scenario === "http" || scenario === "exhausted" ? 3 : ["http-rate", "connection", "timeout", "rate-limit"].includes(scenario) ? 2 : 1);
  });
});

for (const scenario of ["chain", "genesis", "code", "empty code", "beacon", "implementation", "derivation", "second RPC", "remote RPC", "unavailable"]) {
  test(`network verification rejects ${scenario} mismatch`, async () => {
    const cfg = fixture(), good = mockedRpc(cfg);
    const request = async (url, method, params) => {
      if (scenario === "chain" && method === "eth_chainId") return "0x1";
      if (scenario === "genesis" && method === "eth_getBlockByNumber") return { hash: "0x" + "00".repeat(32) };
      if (scenario === "code" && method === "eth_getCode") return "0x6001";
      if (scenario === "empty code" && method === "eth_getCode") return "0x";
      if (scenario === "beacon" && method === "eth_call" && params[0].to === cfg.identity.accountFactory.address && params[0].data.length === 10) return encoded(cfg.identity.entryPoint.address);
      if (scenario === "implementation" && method === "eth_call" && params[0].to === cfg.identity.accountBeacon.address) return encoded(cfg.identity.entryPoint.address);
      if (scenario === "derivation" && method === "eth_call" && params[0].data.length > 10) return encoded(cfg.identity.entryPoint.address);
      if (scenario === "second RPC" && url === cfg.endpoints.rpcUrls[1] && method === "eth_chainId") return "0x1";
      if (scenario === "remote RPC" && url === cfg.endpoints.remoteChains.base.rpcUrls[0] && method === "eth_getCode") return "0x6001";
      if (scenario === "unavailable") throw new Error("secret-error-canary");
      return good(url, method, params);
    };
    await assert.rejects(verifyNetwork(cfg, request), (e) => e.code === "wallet_network_mismatch" && !e.message.includes("secret-error-canary"));
  });
}

test("disabled bridge removes all four tools, remote access and matching docs in both modes", async () => {
  const cfg = structuredClone(MAINNET); cfg.manifest.bridge.enabled = false; identify(cfg);
  for (const bundle of [makeServer(new Ctx(cfg), () => []), await createLocalStdioMcpServer(new Ctx(cfg))]) {
    assert.ok([20, 25].includes(bundle.catalog.length));
    assert.ok(bundle.catalog.every((tool) => !tool.name.includes("bridge")));
    const markdown = renderMarkdown(cfg, bundle.catalog);
    const html = renderHtml(cfg, bundle.catalog);
    for (const document of [markdown, html]) assert.doesNotMatch(document, /get_bridge_routes|build_bridge_transfer|get_bridge_status|Solana/);
    assert.equal((html.match(/<section[ >]/g) ?? []).length, (html.match(/<\/section>/g) ?? []).length);
    await bundle.server.close();
  }
  assert.throws(() => remoteClient(cfg, "base"), /Unknown bridge chain/);
  assert.throws(() => findRoute(cfg, "USDC", "base"));
  const calls = []; const mock = fixture(); mock.manifest.bridge.enabled = false; identify(mock);
  await verifyNetwork(mock, mockedRpc(mock, calls));
  assert.ok(calls.every((c) => mock.endpoints.rpcUrls.includes(c.url)));
});

test("bridge builders use manifest domains and the configured remote endpoint", async () => {
  const cfg = structuredClone(MAINNET);
  cfg.manifest.bridge.incentivDomain = 77;
  cfg.manifest.bridge.remoteChains.base.domain = 88;
  cfg.endpoints.remoteChains.base.rpcUrls = ["https://custom-base.example.test"];
  identify(cfg);
  const route = findRoute(cfg, "USDC", "base");
  const client = remoteClient(cfg, "base");
  assert.equal(client.transport.url, "https://custom-base.example.test");
  const reads = [];
  client.readContract = async (call) => { reads.push(call); return 100n; };
  const recipient = "0x0000000000000000000000000000000000000001";
  const inbound = await buildInboundBridge(cfg, route, recipient, recipient, 1n);
  const outbound = await buildOutboundBridge({ config: cfg, client }, route, recipient, 1n);
  const abi = parseAbi(["function transferRemote(uint32 destination,bytes32 recipient,uint256 amount) payable returns (bytes32)"]);
  assert.equal(decodeFunctionData({ abi, data: inbound.steps.at(-1).data }).args[0], 77);
  assert.equal(decodeFunctionData({ abi, data: outbound.data }).args[0], 88);
  assert.equal(outbound.to, route.localRouter);
  assert.deepEqual(reads.filter((r) => r.functionName === "quoteGasPayment").map((r) => r.args[0]), [77, 88]);
  assert.equal(getBridgeConfig(cfg).remoteChains.base.chainId, 8453);
});

test("bridge tools require an outbound destination and encode exact amounts in both directions", async t => {
  const cfg = fixture(), calls = [], rpc = mockedRpc(cfg, calls), ctx = new Ctx(cfg);
  let estimates = 0;
  t.mock.method(globalThis, "fetch", async (url, options) => {
    const { method, params } = JSON.parse(options.body);
    if (url === cfg.endpoints.bundlerUrl) {
      assert.equal(method, "eth_estimateUserOperationGas"); estimates++;
      return Response.json({ result: { callGasLimit: "0x100", verificationGasLimit: "0x100", preVerificationGas: "0x100" } });
    }
    return Response.json({ result: await rpc(url, method, params) });
  });
  const readContract = async ({ functionName }) => {
    if (functionName === "checkApproval") return { reject: 0 };
    if (functionName === "getNonce" || functionName === "allowance") return 0n;
    if (functionName === "quoteGasPayment") return 100n;
    if (functionName === "balanceOf") return 100000000n;
    assert.fail(functionName);
  };
  ctx.client = { readContract, getBalance: async () => 10n ** 20n, getCode: async () => "0x6000", getBlock: async () => ({ baseFeePerGas: 1n }) };
  t.mock.method(remoteClient(cfg, "ethereum"), "readContract", readContract);
  const bundle = makeServer(ctx, () => []), client = new Client({ name: "bridge-input-test", version: "1" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await bundle.server.connect(b); await client.connect(a);
  t.after(async () => { await client.close(); await bundle.server.close(); });
  const account = "0x0000000000000000000000000000000000000001", recipient = "0x0000000000000000000000000000000000000002";
  const out = { token: "USDC", to_chain: "ethereum", account, amount: "1.000001" };
  const missing = await client.callTool({ name: "build_bridge_transfer_out", arguments: out });
  assert.equal(missing.isError, true); assert.match(missing.content[0].text, /recipient/); assert.equal(calls.length, 0);
  const bridgeAbi = parseAbi(["function transferRemote(uint32 destination,bytes32 recipient,uint256 amount) payable returns (bytes32)"]);
  for (const [name, input] of [
    ["build_bridge_transfer_out", { ...out, recipient }],
    ["build_bridge_transfer", { token: "USDC", from_chain: "ethereum", sender: account, recipient, amount: "1.000001" }],
  ]) {
    for (const amount of ["0", "-1", "1.0000001", (2n ** 256n).toString()]) {
      const invalid = await client.callTool({ name, arguments: { ...input, amount } });
      assert.equal(invalid.isError, true); assert.match(invalid.content[0].text, /Amount/);
    }
    assert.equal(estimates, name === "build_bridge_transfer_out" ? 0 : 1);
    const response = await client.callTool({ name, arguments: input });
    assert.ok(!response.isError, JSON.stringify(response));
    const result = JSON.parse(response.content[0].text);
    const callData = result.user_operation
      ? decodeFunctionData({ abi: accountAbi, data: result.user_operation.callData }).args[2][0]
      : result.unsigned_transactions.at(-1).data;
    const decoded = decodeFunctionData({ abi: bridgeAbi, data: callData });
    assert.equal(decoded.args[1], `0x${"0".repeat(24)}${recipient.slice(2)}`);
    assert.equal(decoded.args[2], 1000001n);
  }
});

test("paymaster configuration cannot leak across network configurations", async () => {
  const make = (coefficient) => ({ config: structuredClone(MAINNET), client: { readContract: async ({ functionName }) =>
    functionName === "usdcToken" ? MAINNET.manifest.canonicalTokens.USDC.address : functionName === "gasEstimateCoefficient" ? coefficient : 1n } });
  const a = make(100n), b = make(200n);
  assert.equal((await getPaymasterConfig(a)).gasEstimateCoefficient, 100n);
  assert.equal((await getPaymasterConfig(b)).gasEstimateCoefficient, 200n);
  assert.equal((await getPaymasterConfig(a)).gasEstimateCoefficient, 100n);
});

test("get_network_status preserves legacy fields and serves a complete verifiable handshake", async (t) => {
  const cfg = structuredClone(MAINNET);
  const ctx = new Ctx(cfg);
  ctx.client = { getBlock: async () => ({ number: 123n, baseFeePerGas: 100n }) };
  ctx.indexer = { listBlocks: async () => ({ items: [{ number: 122 }] }) };
  t.mock.method(globalThis, "fetch", async (url, options) => {
    assert.equal(url, cfg.endpoints.bundlerUrl);
    assert.equal(JSON.parse(options.body).method, "eth_supportedEntryPoints");
    return new Response(JSON.stringify({ result: [cfg.identity.entryPoint.address] }));
  });
  const { server } = makeServer(ctx, () => []);
  const client = new Client({ name: "network-status-test", version: "1" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(b); await client.connect(a);
  try {
    const response = await client.callTool({ name: "get_network_status", arguments: {} });
    assert.ok(!response.isError);
    const status = JSON.parse(response.content[0].text);
    assert.equal(status.chain_id, cfg.identity.chainId);
    assert.equal(status.entry_point, cfg.identity.entryPoint.address);
    assert.equal(status.latest_block, 123);
    assert.equal(status.services.bundler.ok, true);
    assert.equal(status.services.explorer_api.latest_indexed_block, 122);
    assert.deepEqual(status.network_identity, cfg.identity);
    assert.deepEqual(status.capability_manifest, cfg.manifest);
  } finally { await client.close(); await server.close(); }
});
