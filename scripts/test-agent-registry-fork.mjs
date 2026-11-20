// Ephemeral test accounts. This script refuses public RPCs and requires Anvil before sending.
// Start: anvil --fork-url https://rpc.incentiv.io --chain-id 24101 --port 18545
// Run: node --import tsx scripts/test-agent-registry-fork.mjs
import assert from 'node:assert/strict';
import { concatHex, createPublicClient, createWalletClient, defineChain, encodeFunctionData, erc20Abi, http, pad, parseAbi, toHex } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { MAINNET } from '../src/config.ts';
import { deriveSmartAccount } from '../src/network.ts';
import { accountFactoryAbi } from '../src/abi.ts';
import { agentRegistryAbi, assertAgentSignature, hasRegistryEvent, readAgentLinkDigest, registryCall, verifyRegistryIntent } from '../src/agent-registry.ts';
import { computeGasTokenAmount, computeUserOpHash, encodeExecuteBatch, getPaymasterConfig, requiredPaymentUsdc, userOpToJson } from '../src/userop.ts';
import { validateOperation } from '../src/wallet/validate.ts';

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
async function submit(i, deploy, account = agent, owner = agentOwner) {
  const block = await client.getBlock();
  const op = { sender: account, nonce: await client.readContract({ address: entryPoint, abi: entryAbi, functionName: 'getNonce', args: [account, 0n] }), callData: encodeExecuteBatch([registryCall(MAINNET, account, i)]), callGasLimit: 500000n, verificationGasLimit: 1000000n, preVerificationGas: 100000n, maxFeePerGas: block.baseFeePerGas * 2n + 1000000000n, maxPriorityFeePerGas: 1000000000n, signature: '0x', ...(deploy ? { factory: MAINNET.identity.accountFactory.address, factoryData: encodeFunctionData({ abi: accountFactoryAbi, functionName: 'createAccount', args: [owner.address, [zero32, zero32], 0n] }) } : {}) };
  const hash = computeUserOpHash(op, entryPoint, 24101);
  op.signature = await owner.signMessage({ message: { raw: hash } });
  const packed = { sender: account, nonce: op.nonce, initCode: deploy ? concatHex([op.factory, op.factoryData]) : '0x', callData: op.callData, accountGasLimits: concatHex([pad(toHex(op.verificationGasLimit), { size: 16 }), pad(toHex(op.callGasLimit), { size: 16 })]), preVerificationGas: op.preVerificationGas, gasFees: concatHex([pad(toHex(op.maxPriorityFeePerGas), { size: 16 }), pad(toHex(op.maxFeePerGas), { size: 16 })]), paymasterAndData: '0x', signature: op.signature };
  assert.equal(await client.readContract({ address: entryPoint, abi: entryAbi, functionName: 'getUserOpHash', args: [packed] }), hash);
  const tx = await wallet.writeContract({ address: entryPoint, abi: entryAbi, functionName: 'handleOps', args: [[packed], sender.address], gas: 5000000n });
  const receipt = await client.waitForTransactionReceipt({ hash: tx });
  assert.equal(receipt.status, 'success');
  return { receipt, op, hash };
}
// A second agent's approval signed now, at the parent nonce the first link is about to consume.
const staleOwner = privateKeyToAccount(generatePrivateKey()), staleAgent = deriveSmartAccount(MAINNET, staleOwner.address);
await client.request({ method: 'anvil_setBalance', params: [staleAgent, toHex(10n ** 24n)] });
const staleDigest = await client.readContract({ address: registry, abi: agentRegistryAbi, functionName: 'parentLinkDigest', args: [parent, staleAgent, BigInt(deadline)] });
const staleIntent = { ...intent, registryApproval: { ...approval, agent: staleAgent, parent_signature: `0x000000${(await parentOwner.signMessage({ message: { raw: staleDigest } })).slice(2)}` } };
const linked = await submit(intent, true);
assert.ok(hasRegistryEvent(MAINNET, intent, agent, linked.receipt.logs));
assert.equal((await client.readContract({ address: registry, abi: agentRegistryAbi, functionName: 'parentOf', args: [agent] })).toLowerCase(), parent.toLowerCase());
console.log('PASS: Portal-format EOA approval + deployment + link through a real EntryPoint user operation');
// Connections are permanent: MCP refuses to unlink before any registry read, and the link stays.
const unlink = { ...intent, kind: 'unlink_agent', registryApproval: undefined };
const linkedHead = await client.getBlock();
await assert.rejects(verifyRegistryIntent(client, MAINNET, { account: agent }, unlink, { block: linkedHead.number, timestamp: Number(linkedHead.timestamp), deployed: true }), { code: 'registry_unlink_unsupported' });
assert.equal((await client.readContract({ address: registry, abi: agentRegistryAbi, functionName: 'parentOf', args: [agent] })).toLowerCase(), parent.toLowerCase());
console.log('PASS: MCP refuses to unlink the connected agent; the link stays');
// sign_agent_link hands Portal the agent owner's bare EIP-191 signature over the registry's AgentLink digest.
const consentBlock = (await client.getBlock()).number;
const consent = await readAgentLinkDigest(client, MAINNET, agent, parent, BigInt(deadline), consentBlock);
await assertAgentSignature(client, agent, consent.digest, await agentOwner.signMessage({ message: { raw: consent.digest } }), consentBlock);
await assert.rejects(assertAgentSignature(client, agent, consent.digest, await parentOwner.signMessage({ message: { raw: consent.digest } }), consentBlock), { code: 'registry_agent_signature_invalid' });
console.log('PASS: the deployed agent accepts sign_agent_link consent through ERC-1271 and matches the local AgentLink digest');
const fresh = await client.getBlock();
await assert.rejects(verifyRegistryIntent(client, MAINNET, { account: staleAgent }, staleIntent, { block: fresh.number, timestamp: Number(fresh.timestamp), deployed: false }), { code: 'registry_approval_stale' });
console.log("PASS: another agent's parent approval is rejected as stale after the link consumed the parent's registry nonce");
// Deliberately bypass preflight to exercise a nonce race through the real account and EntryPoint.
const failed = await submit(staleIntent, true, staleAgent, staleOwner);
await client.request({ method: 'anvil_mine', params: ['0x2'] });
const receiptChain = new WalletChain(new Ctx(MAINNET));
receiptChain.clients.splice(0, receiptChain.clients.length, client);
const originalFetch = globalThis.fetch;
try {
  // Discovery alone is stubbed: receipt/logs, canonical block and confirmations come from Anvil.
  globalThis.fetch = async (input, init) => String(input) === MAINNET.endpoints.bundlerUrl
    ? Response.json({ result: { receipt: { transactionHash: failed.receipt.transactionHash } } })
    : originalFetch(input, init);
  const result = await receiptChain.receipt({ userOpHash: failed.hash, nonce: failed.op.nonce.toString(), operation: userOpToJson(failed.op), intent: staleIntent });
  assert.equal(result.success, false);
  assert.equal(result.registryError, 'registry_approval_invalid');
  console.log('PASS: stale link reverts through real executeBatch; canonical receipt decodes registry_approval_invalid');
} finally { globalThis.fetch = originalFetch; }

const entryFailureAbi = [...entryAbi, ...parseAbi(['error FailedOp(uint256 opIndex,string reason)', 'error FailedOpWithRevert(uint256 opIndex,string reason,bytes inner)'])];
// Sends calls from any Incentiv account through a real EntryPoint user operation, optionally deploying it and paying gas through the token paymaster.
async function sendOp({ sender: account, owner, calls, deploy = false, paymaster }) {
  const block = await client.getBlock();
  const op = { sender: account, nonce: await client.readContract({ address: entryPoint, abi: entryAbi, functionName: 'getNonce', args: [account, 0n] }), callData: encodeExecuteBatch(calls), callGasLimit: 500000n, verificationGasLimit: paymaster?.verificationGasLimit ?? 1000000n, preVerificationGas: 100000n, maxFeePerGas: block.baseFeePerGas * 2n + 1000000000n, maxPriorityFeePerGas: 1000000000n, signature: '0x',
    ...(deploy ? { factory: MAINNET.identity.accountFactory.address, factoryData: encodeFunctionData({ abi: accountFactoryAbi, functionName: 'createAccount', args: [owner.address, [zero32, zero32], 0n] }) } : {}),
    ...(paymaster ? { paymaster: paymaster.address, paymasterVerificationGasLimit: 300000n, paymasterPostOpGasLimit: 50000n, paymasterData: '0x' } : {}) };
  const hash = computeUserOpHash(op, entryPoint, 24101);
  op.signature = await owner.signMessage({ message: { raw: hash } });
  const packed = { sender: account, nonce: op.nonce, initCode: deploy ? concatHex([op.factory, op.factoryData]) : '0x', callData: op.callData, accountGasLimits: concatHex([pad(toHex(op.verificationGasLimit), { size: 16 }), pad(toHex(op.callGasLimit), { size: 16 })]), preVerificationGas: op.preVerificationGas, gasFees: concatHex([pad(toHex(op.maxPriorityFeePerGas), { size: 16 }), pad(toHex(op.maxFeePerGas), { size: 16 })]),
    paymasterAndData: paymaster ? concatHex([op.paymaster, pad(toHex(op.paymasterVerificationGasLimit), { size: 16 }), pad(toHex(op.paymasterPostOpGasLimit), { size: 16 })]) : '0x', signature: op.signature };
  // Simulate first, so an EntryPoint validation failure reports its reason instead of a bare reverted transaction.
  await client.simulateContract({ address: entryPoint, abi: entryFailureAbi, functionName: 'handleOps', args: [[packed], sender.address], account: sender, gas: 6000000n });
  const receipt = await client.waitForTransactionReceipt({ hash: await wallet.writeContract({ address: entryPoint, abi: entryAbi, functionName: 'handleOps', args: [[packed], sender.address], gas: 6000000n }) });
  assert.equal(receipt.status, 'success');
  return { receipt, op, hash };
}
const deployAccount = async owner => client.waitForTransactionReceipt({ hash: await wallet.writeContract({ address: MAINNET.identity.accountFactory.address, abi: accountFactoryAbi, functionName: 'createAccount', args: [owner.address, [zero32, zero32], 0n], gas: 2000000n }) });
const forkChain = () => { const c = new WalletChain(new Ctx(MAINNET)); c.clients.splice(0, c.clients.length, client); return c; };
const parentOf = async account => (await client.readContract({ address: registry, abi: agentRegistryAbi, functionName: 'parentOf', args: [account] })).toLowerCase();
const zeroAddress = `0x${'00'.repeat(20)}`;
// Discovery alone is stubbed: receipts, logs, canonical block and confirmations come from Anvil.
async function decodeReceipt(sent, intent) {
  await client.request({ method: 'anvil_mine', params: ['0x2'] });
  const fetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => String(input) === MAINNET.endpoints.bundlerUrl ? Response.json({ result: { receipt: { transactionHash: sent.receipt.transactionHash } } }) : fetch(input, init);
  try { return await forkChain().receipt({ userOpHash: sent.hash, nonce: sent.op.nonce.toString(), operation: userOpToJson(sent.op), intent }); }
  finally { globalThis.fetch = fetch; }
}

// Portal-submitted link: sign_agent_link's chain path makes the consent, then the parent account sends link() itself.
const agent2Owner = privateKeyToAccount(generatePrivateKey()), agent2 = deriveSmartAccount(MAINNET, agent2Owner.address);
await deployAccount(agent2Owner);
await client.request({ method: 'anvil_setBalance', params: [agent2, toHex(10n ** 27n)] });
await client.request({ method: 'anvil_mine', params: ['0x1'] });
const envelope2 = { account: agent2, owner: agent2Owner.address, approvedCapabilityManifestId: MAINNET.manifest.manifestId };
const signed = await forkChain().agentLinkConsent(envelope2, parent, undefined);
assert.equal(signed.blocked, undefined); assert.ok(signed.consent);
const agentSig = await agent2Owner.signMessage({ message: { raw: signed.consent.digest } });
await forkChain().verifyAgentLinkSignature(envelope2, signed.consent.digest, agentSig, signed.consent.block);
const portalLink = await sendOp({ sender: parent, owner: parentOwner, calls: [{ to: registry, value: 0n, data: encodeFunctionData({ abi: agentRegistryAbi, functionName: 'link', args: [parent, agent2, 0n, '0x', signed.consent.deadline, agentSig] }) }] });
assert.equal(await parentOf(agent2), parent.toLowerCase(), 'Portal-submitted link reverted inside executeBatch');
assert.ok(hasRegistryEvent(MAINNET, { kind: 'link_agent', registryParent: parent }, agent2, portalLink.receipt.logs));
assert.equal(await client.readContract({ address: registry, abi: agentRegistryAbi, functionName: 'nonces', args: [agent2] }), signed.consent.nonce + 1n);
console.log('PASS: sign_agent_link consent + Portal-submitted link from the parent account; the agent nonce is spent');

// No disconnect in Portal or MCP: status shows the link, and the agent cannot remove it.
await client.request({ method: 'anvil_mine', params: ['0x1'] });
assert.equal((await forkChain().registryStatus(envelope2)).parent.toLowerCase(), parent.toLowerCase());
await assert.rejects(forkChain().verifyRegistry(envelope2, { ...unlink, registryParent: parent }), { code: 'registry_unlink_unsupported' });
console.log('PASS: MCP status shows the Portal-submitted link, and the agent cannot unlink it');

// Token-paid first operation: a USDC-paid link that also deploys the agent, through the real token paymaster.
const usdc = MAINNET.manifest.canonicalTokens.USDC.address, paymasterAddress = MAINNET.manifest.contracts.unifiedTokenPaymaster.address;
const agent3Owner = privateKeyToAccount(generatePrivateKey()), agent3 = deriveSmartAccount(MAINNET, agent3Owner.address);
await client.request({ method: 'anvil_setBalance', params: [agent3, '0x0'] });
const funded = 1000n * 10n ** 6n;
// Fund the agent from a recent USDC recipient that still holds enough, impersonated on the fork only.
const latest = await client.getBlockNumber();
const transfers = await client.getLogs({ address: usdc, event: parseAbi(['event Transfer(address indexed from,address indexed to,uint256 value)'])[0], fromBlock: latest > 50000n ? latest - 50000n : 0n, toBlock: latest });
let holder;
for (const log of transfers.reverse()) {
  const candidate = log.args.to;
  if (!candidate || candidate === zeroAddress) continue;
  if (await client.readContract({ address: usdc, abi: erc20Abi, functionName: 'balanceOf', args: [candidate] }) >= funded) { holder = candidate; break; }
}
assert.ok(holder, 'No recent USDC holder with enough balance to fund the fork test');
await client.request({ method: 'anvil_impersonateAccount', params: [holder] });
await client.request({ method: 'anvil_setBalance', params: [holder, toHex(10n ** 21n)] });
const holderWallet = createWalletClient({ chain, account: holder, transport: http(rpc, { timeout: 60000 }) });
await client.waitForTransactionReceipt({ hash: await holderWallet.writeContract({ address: usdc, abi: erc20Abi, functionName: 'transfer', args: [agent3, funded], gas: 200000n }) });
await client.request({ method: 'anvil_stopImpersonatingAccount', params: [holder] });
assert.equal(await client.readContract({ address: usdc, abi: erc20Abi, functionName: 'balanceOf', args: [agent3] }), funded);
// The paymaster pays only for trusted bundlers (tx.origin). On this fork only, its owner trusts the test's submitter.
const paymasterAdminAbi = parseAbi(['function owner() view returns(address)', 'function setTrustedBundler(address bundler,bool trusted)', 'function trustedBundlers(address) view returns(bool)']);
const paymasterOwner = await client.readContract({ address: paymasterAddress, abi: paymasterAdminAbi, functionName: 'owner' });
await client.request({ method: 'anvil_impersonateAccount', params: [paymasterOwner] });
await client.request({ method: 'anvil_setBalance', params: [paymasterOwner, toHex(10n ** 21n)] });
const ownerWallet = createWalletClient({ chain, account: paymasterOwner, transport: http(rpc, { timeout: 60000 }) });
await client.waitForTransactionReceipt({ hash: await ownerWallet.writeContract({ address: paymasterAddress, abi: paymasterAdminAbi, functionName: 'setTrustedBundler', args: [sender.address, true], gas: 200000n }) });
await client.request({ method: 'anvil_stopImpersonatingAccount', params: [paymasterOwner] });
assert.equal(await client.readContract({ address: paymasterAddress, abi: paymasterAdminAbi, functionName: 'trustedBundlers', args: [sender.address] }), true);
const tokenDeadline = Math.floor(Date.now() / 1000) + 900;
const tokenNonce = await client.readContract({ address: registry, abi: agentRegistryAbi, functionName: 'nonces', args: [parent] });
const tokenDigest = await client.readContract({ address: registry, abi: agentRegistryAbi, functionName: 'parentLinkDigest', args: [parent, agent3, BigInt(tokenDeadline)] });
const tokenApproval = { version: 1, chain_id: 24101, registry, parent, agent: agent3, parent_nonce: tokenNonce.toString(), parent_deadline: String(tokenDeadline), parent_signature: `0x000000${(await parentOwner.signMessage({ message: { raw: tokenDigest } })).slice(2)}` };
const tokenIntent = { intentSchemaVersion: 1, kind: 'link_agent', token: usdc, gasToken: usdc, amount: '0', slippageBps: 0, feeTier: 3000, registryParent: parent, registryApproval: tokenApproval };
const forkCtx = new Ctx({ ...MAINNET, endpoints: { ...MAINNET.endpoints, rpcUrls: [rpc] } });
const pm = await getPaymasterConfig(forkCtx);
const verificationGasLimit = pm.maxVerificationGas !== 0n && pm.maxVerificationGas < 1000000n ? pm.maxVerificationGas : 1000000n;
// Price at a quarter of mainnet's base fee, below this year's low: the paymaster's USDC schedule does not depend on it,
// so a price that scaled with the base fee would be refused here as "Payment below minimum".
await client.request({ method: 'anvil_setNextBlockBaseFeePerGas', params: [toHex(forkHead.baseFeePerGas / 4n)] });
await client.request({ method: 'anvil_mine', params: ['0x1'] });
const quoteBlock = await client.getBlock();
const gasCharge = await computeGasTokenAmount(forkCtx, pm, { address: usdc, symbol: 'USDC', name: 'USD Coin', decimals: 6 }, await requiredPaymentUsdc(forkCtx, pm, { callGasLimit: 500000n, preVerificationGas: 100000n }));
const tokenCalls = [{ to: usdc, value: 0n, data: encodeFunctionData({ abi: erc20Abi, functionName: 'transfer', args: [paymasterAddress, gasCharge] }) }, registryCall(MAINNET, agent3, tokenIntent)];
const tokenSent = await sendOp({ sender: agent3, owner: agent3Owner, calls: tokenCalls, deploy: true, paymaster: { address: paymasterAddress, verificationGasLimit } });
// The wallet's own validator accepts the operation that the real paymaster just paid for.
validateOperation(MAINNET, { account: agent3, owner: agent3Owner.address, approvedCapabilityManifestId: MAINNET.manifest.manifestId }, tokenIntent, userOpToJson({ ...tokenSent.op, signature: '0x' }), { nonce: tokenSent.op.nonce, deployed: false, hash: tokenSent.hash, deadline: tokenDeadline });
const tokenResult = await decodeReceipt(tokenSent, tokenIntent);
assert.equal(tokenResult.success, true); assert.equal(tokenResult.registryError, undefined);
assert.equal(await parentOf(agent3), parent.toLowerCase());
assert.equal(await client.getBalance({ address: agent3 }), 0n, 'The agent paid no native gas');
assert.equal(await client.readContract({ address: usdc, abi: erc20Abi, functionName: 'balanceOf', args: [agent3] }), funded - gasCharge);
console.log(`PASS: USDC-paid first operation deploys and links the agent through the real paymaster at a base fee of ${quoteBlock.baseFeePerGas / 10n ** 9n} gwei (charged ${gasCharge} USDC units by the paymaster's schedule); wallet validation and receipt agree`);

// WCENT gas: the paymaster converts the USDC schedule to WCENT with a live pool quote, so the wallet's margin must cover it.
// A fourth agent deploys and links itself paying in WCENT.
const wcent = MAINNET.manifest.contracts.wcent.address, wcentAbi = parseAbi(['function deposit() payable']);
const agent4Owner = privateKeyToAccount(generatePrivateKey()), agent4 = deriveSmartAccount(MAINNET, agent4Owner.address);
// Fund it from the test submitter: a transaction sent as the undeployed address would give it a nonce and block its deployment.
await client.waitForTransactionReceipt({ hash: await wallet.writeContract({ address: wcent, abi: wcentAbi, functionName: 'deposit', value: 10n ** 21n, gas: 200000n }) });
await client.waitForTransactionReceipt({ hash: await wallet.writeContract({ address: wcent, abi: erc20Abi, functionName: 'transfer', args: [agent4, 10n ** 21n], gas: 200000n }) });
const wcentBefore = await client.readContract({ address: wcent, abi: erc20Abi, functionName: 'balanceOf', args: [agent4] });
const wcentDeadline = Math.floor(Date.now() / 1000) + 900;
const wcentNonce = await client.readContract({ address: registry, abi: agentRegistryAbi, functionName: 'nonces', args: [parent] });
const wcentDigest = await client.readContract({ address: registry, abi: agentRegistryAbi, functionName: 'parentLinkDigest', args: [parent, agent4, BigInt(wcentDeadline)] });
const wcentApproval = { version: 1, chain_id: 24101, registry, parent, agent: agent4, parent_nonce: wcentNonce.toString(), parent_deadline: String(wcentDeadline), parent_signature: `0x000000${(await parentOwner.signMessage({ message: { raw: wcentDigest } })).slice(2)}` };
const link4 = { intentSchemaVersion: 1, kind: 'link_agent', token: wcent, gasToken: wcent, amount: '0', slippageBps: 0, feeTier: 3000, registryParent: parent, registryApproval: wcentApproval };
const wcentCharge = await computeGasTokenAmount(forkCtx, pm, { address: wcent, symbol: 'WCENT', name: 'Wrapped CENT', decimals: 18 }, await requiredPaymentUsdc(forkCtx, pm, { callGasLimit: 500000n, preVerificationGas: 100000n }));
const wcentSent = await sendOp({ sender: agent4, owner: agent4Owner, calls: [{ to: wcent, value: 0n, data: encodeFunctionData({ abi: erc20Abi, functionName: 'transfer', args: [paymasterAddress, wcentCharge] }) }, registryCall(MAINNET, agent4, link4)], deploy: true, paymaster: { address: paymasterAddress, verificationGasLimit } });
validateOperation(MAINNET, { account: agent4, owner: agent4Owner.address, approvedCapabilityManifestId: MAINNET.manifest.manifestId }, link4, userOpToJson({ ...wcentSent.op, signature: '0x' }), { nonce: wcentSent.op.nonce, deployed: false, hash: wcentSent.hash, deadline: wcentDeadline });
const wcentResult = await decodeReceipt(wcentSent, link4);
assert.equal(wcentResult.success, true); assert.equal(await parentOf(agent4), parent.toLowerCase());
assert.equal(await client.getBalance({ address: agent4 }), 0n, 'The agent paid no native gas');
assert.equal(await client.readContract({ address: wcent, abi: erc20Abi, functionName: 'balanceOf', args: [agent4] }), wcentBefore - wcentCharge);
console.log(`PASS: WCENT-paid first operation deploys and links an agent through the real paymaster's live USDC-to-WCENT quote (charged ${wcentCharge} WCENT wei)`);


} finally { await client.request({ method: 'evm_revert', params: [snapshot] }); }
