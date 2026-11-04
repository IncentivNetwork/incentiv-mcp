// Ephemeral test accounts. This script refuses public RPCs and requires Anvil before sending.
// Start: anvil --fork-url https://rpc.incentiv.io --chain-id 24101 --port 18545
// Run: node --import tsx scripts/test-agent-registry-fork.mjs
import assert from 'node:assert/strict';
import { concatHex, createPublicClient, createWalletClient, defineChain, encodeFunctionData, http, pad, parseAbi, toHex } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { MAINNET } from '../src/config.ts';
import { deriveSmartAccount } from '../src/network.ts';
import { accountFactoryAbi } from '../src/abi.ts';
import { agentRegistryAbi, hasRegistryEvent, registryCall, verifyRegistryIntent } from '../src/agent-registry.ts';
import { computeUserOpHash, userOpToJson, encodeExecuteBatch } from '../src/userop.ts';

import { Ctx } from '../src/context.ts';
import { WalletChain } from '../src/wallet/chain.ts';

const rpc = process.env.INCENTIV_REGISTRY_FORK_RPC ?? 'http://127.0.0.1:18545';
assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(new URL(rpc).hostname), 'Use a loopback Anvil fork only');
const chain = defineChain({ id: 24101, name: 'Local Incentiv fork', nativeCurrency: { name: 'CENT', symbol: 'CENT', decimals: 18 }, rpcUrls: { default: { http: [rpc] } } });
const client = createPublicClient({ chain, transport: http(rpc, { timeout: 60000 }) });
await client.request({ method: 'anvil_nodeInfo' });
assert.equal(await client.getChainId(), 24101);
const snapshot = await client.request({ method: 'evm_snapshot' });
try {
// A pinned fork can be older than preflight's freshness window. Mine our first local
// transaction at the current time without changing the public chain.
const forkHead = await client.getBlock();
await client.request({ method: 'evm_setNextBlockTimestamp', params: [Math.max(Math.floor(Date.now() / 1000), Number(forkHead.timestamp) + 1)] });
const sender = privateKeyToAccount(generatePrivateKey());
const parentOwner = privateKeyToAccount(generatePrivateKey());
const agentOwner = privateKeyToAccount(generatePrivateKey());
const wallet = createWalletClient({ chain, account: sender, transport: http(rpc, { timeout: 60000 }) });
const parent = deriveSmartAccount(MAINNET, parentOwner.address), agent = deriveSmartAccount(MAINNET, agentOwner.address);
const registry = MAINNET.manifest.agentRegistry.proxy.address, entryPoint = MAINNET.identity.entryPoint.address;
for (const address of [sender.address, parent, agent]) await client.request({ method: 'anvil_setBalance', params: [address, toHex(10n ** 27n)] });
const zero32 = toHex(0n, { size: 32 });
await client.waitForTransactionReceipt({ hash: await wallet.writeContract({ address: MAINNET.identity.accountFactory.address, abi: accountFactoryAbi, functionName: 'createAccount', args: [parentOwner.address, [zero32, zero32], 0n], gas: 2000000n }) });
assert.equal(await client.getCode({ address: agent }), undefined, 'Agent must start undeployed');
const deadline = Math.floor(Date.now() / 1000) + 900;
const nonce = await client.readContract({ address: registry, abi: agentRegistryAbi, functionName: 'nonces', args: [parent] });
const digest = await client.readContract({ address: registry, abi: agentRegistryAbi, functionName: 'parentLinkDigest', args: [parent, agent, BigInt(deadline)] });
const signature = await parentOwner.signMessage({ message: { raw: digest } });
const approval = { version: 1, chain_id: 24101, registry, parent, agent, parent_nonce: nonce.toString(), parent_deadline: String(deadline), parent_signature: `0x000000${signature.slice(2)}` };
const intent = { intentSchemaVersion: 1, kind: 'link_agent', token: 'native', gasToken: 'native', amount: '0', slippageBps: 0, feeTier: 3000, registryParent: parent, registryApproval: approval };
const head = await client.getBlock();
await verifyRegistryIntent(client, MAINNET, { account: agent }, intent, { block: head.number, timestamp: Number(head.timestamp), deployed: false });
const entryAbi = parseAbi([
  'function handleOps((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature)[] ops,address beneficiary)',
  'function getNonce(address,uint192) view returns(uint256)',
  'function getUserOpHash((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature) op) view returns(bytes32)',
]);
async function submit(i, deploy) {
  const block = await client.getBlock();
  const op = { sender: agent, nonce: await client.readContract({ address: entryPoint, abi: entryAbi, functionName: 'getNonce', args: [agent, 0n] }), callData: encodeExecuteBatch([registryCall(MAINNET, agent, i)]), callGasLimit: 500000n, verificationGasLimit: 1000000n, preVerificationGas: 100000n, maxFeePerGas: block.baseFeePerGas * 2n + 1000000000n, maxPriorityFeePerGas: 1000000000n, signature: '0x', ...(deploy ? { factory: MAINNET.identity.accountFactory.address, factoryData: encodeFunctionData({ abi: accountFactoryAbi, functionName: 'createAccount', args: [agentOwner.address, [zero32, zero32], 0n] }) } : {}) };
  const hash = computeUserOpHash(op, entryPoint, 24101);
  op.signature = await agentOwner.signMessage({ message: { raw: hash } });
  const packed = { sender: agent, nonce: op.nonce, initCode: deploy ? concatHex([op.factory, op.factoryData]) : '0x', callData: op.callData, accountGasLimits: concatHex([pad(toHex(op.verificationGasLimit), { size: 16 }), pad(toHex(op.callGasLimit), { size: 16 })]), preVerificationGas: op.preVerificationGas, gasFees: concatHex([pad(toHex(op.maxPriorityFeePerGas), { size: 16 }), pad(toHex(op.maxFeePerGas), { size: 16 })]), paymasterAndData: '0x', signature: op.signature };
  assert.equal(await client.readContract({ address: entryPoint, abi: entryAbi, functionName: 'getUserOpHash', args: [packed] }), hash);
  const tx = await wallet.writeContract({ address: entryPoint, abi: entryAbi, functionName: 'handleOps', args: [[packed], sender.address], gas: 5000000n });
  const receipt = await client.waitForTransactionReceipt({ hash: tx });
  assert.equal(receipt.status, 'success');
  return { receipt, op, hash };
}
const linked = await submit(intent, true);
assert.ok(hasRegistryEvent(MAINNET, intent, agent, linked.receipt.logs));
assert.equal((await client.readContract({ address: registry, abi: agentRegistryAbi, functionName: 'parentOf', args: [agent] })).toLowerCase(), parent.toLowerCase());
console.log('PASS: Portal-format EOA approval + deployment + link through a real EntryPoint user operation');
const unlink = { ...intent, kind: 'unlink_agent', registryApproval: undefined };
const unlinked = await submit(unlink, false);
assert.ok(hasRegistryEvent(MAINNET, unlink, agent, unlinked.receipt.logs));
assert.equal(await client.readContract({ address: registry, abi: agentRegistryAbi, functionName: 'parentOf', args: [agent] }), `0x${'00'.repeat(20)}`);
console.log('PASS: agent unlink through a real EntryPoint user operation');
const fresh = await client.getBlock();
await assert.rejects(verifyRegistryIntent(client, MAINNET, { account: agent }, intent, { block: fresh.number, timestamp: Number(fresh.timestamp), deployed: true }), { code: 'registry_approval_stale' });
console.log('PASS: old parent approval rejected after link/unlink consumed registry nonces');
// Deliberately bypass preflight to exercise a nonce race through the real account and EntryPoint.
const failed = await submit(intent, false);
await client.request({ method: 'anvil_mine', params: ['0x2'] });
const receiptChain = new WalletChain(new Ctx(MAINNET));
receiptChain.clients.splice(0, receiptChain.clients.length, client);
const originalFetch = globalThis.fetch;
try {
  // Discovery alone is stubbed: receipt/logs, canonical block and confirmations come from Anvil.
  globalThis.fetch = async (input, init) => String(input) === MAINNET.endpoints.bundlerUrl
    ? Response.json({ result: { receipt: { transactionHash: failed.receipt.transactionHash } } })
    : originalFetch(input, init);
  const result = await receiptChain.receipt({ userOpHash: failed.hash, nonce: failed.op.nonce.toString(), operation: userOpToJson(failed.op), intent });
  assert.equal(result.success, false);
  assert.equal(result.registryError, 'registry_approval_invalid');
  console.log('PASS: stale link reverts through real executeBatch; canonical receipt decodes registry_approval_invalid');
} finally { globalThis.fetch = originalFetch; }


} finally { await client.request({ method: 'evm_revert', params: [snapshot] }); }
