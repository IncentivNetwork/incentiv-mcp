// Live checks against mainnet. Verifies the userOpHash and the signing scheme
// against the deployed EntryPoint and SignatureVerifier. No funds required.
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { parseAbi, keccak256, stringToHex } from "viem";
import { loadConfig } from "./dist/config.js";
import { Ctx } from "./dist/context.js";
import { computeUserOpHash, buildUserOpUnsigned, userOpFromJson, getFees } from "./dist/userop.js";
import { planRoute, quoteRoute } from "./dist/swap.js";
import { entryPointAbi } from "./dist/abi.js";

const ctx = new Ctx(loadConfig());

// Local userOpHash must match EntryPoint.getUserOpHash.
const op = {
  sender: "0x2b2d67f51c5ae1e00eaeb1ea3c8a984a3bc9c8d6",
  nonce: 7n,
  callData: "0xdeadbeef",
  callGasLimit: 111n,
  verificationGasLimit: 222n,
  preVerificationGas: 333n,
  maxFeePerGas: 444n,
  maxPriorityFeePerGas: 555n,
  signature: "0x",
};
const local = computeUserOpHash(op, ctx.config.identity.entryPoint.address, ctx.config.identity.chainId);
const packed = {
  sender: op.sender,
  nonce: op.nonce,
  initCode: "0x",
  callData: op.callData,
  accountGasLimits: "0x" + op.verificationGasLimit.toString(16).padStart(32, "0") + op.callGasLimit.toString(16).padStart(32, "0"),
  preVerificationGas: op.preVerificationGas,
  gasFees: "0x" + op.maxPriorityFeePerGas.toString(16).padStart(32, "0") + op.maxFeePerGas.toString(16).padStart(32, "0"),
  paymasterAndData: "0x",
  signature: "0x",
};
const onchain = await ctx.client.readContract({
  address: ctx.config.identity.entryPoint.address,
  abi: entryPointAbi,
  functionName: "getUserOpHash",
  args: [packed],
});
console.log("hash local == entrypoint:", local === onchain);

// Signing scheme against the on-chain SignatureVerifier.
const owner = privateKeyToAccount(generatePrivateKey());
const verifierAbi = parseAbi([
  "function verifySignature(bytes owner, bytes message, bytes signature) view returns (bool isValid, address accountAddress)",
]);
const msg = "incentiv-mcp signature test";
const sig = await owner.signMessage({ message: { raw: keccak256(stringToHex(msg)) } });
const [isValid] = await ctx.client.readContract({
  address: "0xd44EbfDf4FFf3e367b7e07e47eA0e70F5277Bca0",
  abi: verifierAbi,
  functionName: "verifySignature",
  args: [owner.address, stringToHex(msg), sig],
});
console.log("verifier accepts EIP-191 owner signature:", isValid);

// Build an unsigned operation and confirm the hash survives a JSON round trip.
const deployed = "0x2b2d67f51c5ae1e00eaeb1ea3c8a984a3bc9c8d6"; // a real deployed IncentivAccount
const prepared = await buildUserOpUnsigned(ctx, {
  account: deployed,
  calls: [{ to: "0x0000000000000000000000000000000000000001", value: 0n, data: "0x" }],
});
const parsed = userOpFromJson({ ...toJson(prepared.op) });
const rebuiltHash = computeUserOpHash(parsed, ctx.config.identity.entryPoint.address, ctx.config.identity.chainId);
console.log("build produced non-empty callData:", prepared.op.callData.length > 10);
console.log("build sign_hash stable through JSON round-trip:", rebuiltHash === prepared.userOpHash);
console.log("build op has empty signature (client signs):", prepared.op.signature === "0x");
console.log("estimated gas > 0:", prepared.op.callGasLimit > 0n && prepared.op.verificationGasLimit > 0n);

function toJson(o) {
  const j = {};
  for (const [k, v] of Object.entries(o)) j[k] = typeof v === "bigint" ? "0x" + v.toString(16) : v;
  return j;
}

// Swap quotes.
const usdc = await ctx.resolveToken("USDC");
const weth = await ctx.resolveToken("USDT");
const route = planRoute(ctx, usdc, weth);
const q = await quoteRoute(ctx, route, 10n ** BigInt(usdc.decimals));
console.log("route:", route.description, "| 1 USDC ->", Number(q.amountOut) / 10 ** weth.decimals, weth.symbol);
console.log("fees:", await getFees(ctx));
console.log("DONE");
