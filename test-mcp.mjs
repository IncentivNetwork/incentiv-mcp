// End-to-end test over stdio: read, build unsigned, sign locally, broadcast.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { computeUserOpHash } from "./dist/userop.js";
import { loadConfig } from "./dist/config.js";

const cfg = loadConfig();

async function withServer(fn) {
  const client = new Client({ name: "test", version: "0.0.0" });
  const transport = new StdioClientTransport({ command: "node", args: ["dist/index.js"], stderr: "pipe" });
  await client.connect(transport);
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}
const parse = (res) => JSON.parse(res.content?.[0]?.text ?? "{}");
const show = (name, res) => {
  const text = res.content?.[0]?.text ?? "";
  console.log(`\n--- ${name}${res.isError ? " [ERROR]" : ""} ---`);
  console.log(text.length > 600 ? text.slice(0, 600) + " …" : text);
};

await withServer(async (c) => {
  const tools = (await c.listTools()).tools.map((t) => t.name);
  console.log("tools:", tools.join(", "));
  // The server must expose read, build and broadcast tools, and no signing tool.
  for (const must of ["build_transfer", "build_swap", "broadcast_user_operation", "build_transaction", "broadcast_transaction"])
    if (!tools.includes(must)) throw new Error(`missing tool ${must}`);
  if (tools.some((t) => t.startsWith("place_") || t.startsWith("review_"))) throw new Error("stale write tools present!");

  show("get_network_status", await c.callTool({ name: "get_network_status", arguments: {} }));
  show("get_portfolio", await c.callTool({ name: "get_portfolio", arguments: { address: "0x24dd55e6faf4f31513eba24397dfa63a353feef3" } }));
  show("get_swap_quote 5 USDC->CENT", await c.callTool({ name: "get_swap_quote", arguments: { token_in: "USDC", token_out: "CENT", amount_in: "5" } }));

  // Build an unsigned transfer for a deployed account.
  const deployed = "0x2b2d67f51c5ae1e00eaeb1ea3c8a984a3bc9c8d6";
  const built = parse(await c.callTool({ name: "build_transfer", arguments: { account: deployed, token: "USDC", to: "0x0000000000000000000000000000000000000001", amount: "0.01" } }));
  show("build_transfer", { content: [{ type: "text", text: JSON.stringify({ action: built.action, sign_hash: built.sign_hash, gas_payment: built.gas_payment, has_unsigned_op: !!built.user_operation, sig: built.user_operation?.signature }) }] });
  if (!built.sign_hash || !built.user_operation) throw new Error("build_transfer did not return a signable op");
  if (built.user_operation.signature !== "0x") throw new Error("build_transfer returned a pre-filled signature (should be empty)");

  // Sign the returned hash locally.
  const owner = privateKeyToAccount(generatePrivateKey());
  const signature = await owner.signMessage({ message: { raw: built.sign_hash } });
  console.log("\nclient signed sign_hash locally (server holds no key):", signature.slice(0, 20) + "…");

  // The returned sign_hash must recompute from the returned operation.
  const op = built.user_operation;
  const recomputed = computeUserOpHash(
    { sender: op.sender, nonce: BigInt(op.nonce), callData: op.callData, callGasLimit: BigInt(op.callGasLimit), verificationGasLimit: BigInt(op.verificationGasLimit), preVerificationGas: BigInt(op.preVerificationGas), maxFeePerGas: BigInt(op.maxFeePerGas), maxPriorityFeePerGas: BigInt(op.maxPriorityFeePerGas), signature: "0x", ...(op.paymaster ? { paymaster: op.paymaster, paymasterVerificationGasLimit: BigInt(op.paymasterVerificationGasLimit), paymasterPostOpGasLimit: BigInt(op.paymasterPostOpGasLimit), paymasterData: op.paymasterData } : {}) },
    cfg.identity.entryPoint.address, cfg.identity.chainId,
  );
  console.log("server sign_hash matches recomputed hash of returned op:", recomputed === built.sign_hash);

  // A wrong owner fails bundler validation, which confirms the wire format and
  // broadcast path. It must not fail as a format or parse error.
  const b = await c.callTool({ name: "broadcast_user_operation", arguments: { user_operation: op, signature, wait: false } });
  show("broadcast_user_operation (wrong-owner sig → bundler validation error expected)", b);
  const btext = b.content?.[0]?.text ?? "";
  if (btext.includes("missing required field") || btext.includes("parse")) throw new Error("broadcast rejected on format, not validation");

  // Build an unsigned EOA transaction.
  show("build_transaction (EOA)", await c.callTool({ name: "build_transaction", arguments: { from: "0xce3cc056a1dff0c9322c4b223e59e963ae18e65b", to: "0x0000000000000000000000000000000000000001", value: "0.1" } }));


  show("build_swap USDC->USDT", await c.callTool({ name: "build_swap", arguments: { account: deployed, token_in: "USDC", token_out: "USDT", amount_in: "1", gas_token: "USDC" } }));


  show("search USDC", await c.callTool({ name: "search", arguments: { query: "USDC" } }));
});
console.log("\nALL MCP TESTS DONE");
