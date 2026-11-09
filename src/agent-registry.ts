import { BaseError, ContractFunctionRevertedError, ContractFunctionZeroDataError, InternalRpcError, decodeErrorResult, decodeEventLog, encodeFunctionData, getAddress, getContract, keccak256, parseAbi, type Address, type Hex, type PublicClient } from "viem";
import { z } from "zod";
import type { Config } from "./config.js";
import type { Intent } from "./wallet/journal.js";
import { WalletError } from "./wallet/errors.js";
import { uint } from "./wallet/policy.js";

export const REGISTRY_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
export const agentRegistryAbi = parseAbi([
  "function link(address parent,address agent,uint256 parentDeadline,bytes parentSig,uint256 agentDeadline,bytes agentSig)",
  "function unlink()", "function unlinkAgent(address agent)", "function invalidateNonce()",
  "function parentOf(address agent) view returns(address)", "function agentsOf(address parent) view returns(address[])",
  "function agentCount(address parent) view returns(uint256)", "function maxAgentsPerParent() view returns(uint256)",
  "function isIncentivAccount(address account) view returns(bool)", "function isAccountFactory(address factory) view returns(bool)",
  "function parentLinkDigest(address parent,address agent,uint256 deadline) view returns(bytes32)",
  "function nonces(address account) view returns(uint256)",
  "function eip712Domain() view returns(bytes1 fields,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt,uint256[] extensions)",
  "event AgentLinked(address indexed parent,address indexed agent)",
  "event AgentUnlinked(address indexed parent,address indexed agent,address indexed by)",
  "error AgentLimitReached(address parent,uint256 maxAgents)", "error AgentAlreadyHasParent(address agent)",
  "error ParentIsAgent(address parent)", "error AgentIsParent(address agent)",
  "error ParentNotIncentivAccount(address parent)", "error AgentNotIncentivAccount(address agent)",
  "error NotLinked(address account)", "error SelfLink()",
  "error InvalidParentSignature()", "error InvalidAgentSignature()", "error SignatureExpired(uint256 deadline)",
]);
const accountSignatureAbi = parseAbi(["function isValidSignature(bytes32 hash,bytes signature) view returns(bytes4)"]);
const addr = z.string().regex(/^0x[0-9a-fA-F]{40}$/).refine(a => !/^0x0{40}$/i.test(a));
export const registryApprovalSchema = z.strictObject({
  version: z.literal(1), chain_id: z.number().int().positive().max(Number.MAX_SAFE_INTEGER), registry: addr,
  parent: addr, agent: addr, parent_nonce: uint,
  parent_deadline: uint.refine(s => BigInt(s) <= BigInt(Number.MAX_SAFE_INTEGER)),
  // Generous for EOA and passkey signatures; every accepted request occupies the capped journal.
  parent_signature: z.string().max(8194).regex(/^0x(?:[0-9a-fA-F]{2})+$/),
});
export type RegistryApproval = z.infer<typeof registryApprovalSchema>;
export function registryRevertCode(data: Hex): string | undefined {
  try {
    const { errorName } = decodeErrorResult({ abi: agentRegistryAbi, data });
    return ({ NotLinked: "registry_link_changed", SelfLink: "registry_ineligible", InvalidAgentSignature: "registry_agent_signature_invalid", InvalidParentSignature: "registry_approval_invalid", SignatureExpired: "registry_approval_expired", AgentLimitReached: "registry_limit_reached", AgentAlreadyHasParent: "registry_already_linked", ParentIsAgent: "registry_ineligible", AgentIsParent: "registry_ineligible", ParentNotIncentivAccount: "registry_ineligible", AgentNotIncentivAccount: "registry_ineligible" } as Record<string, string>)[errorName];
  } catch { return undefined; }
}
export const sameAddress = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
/** The contract itself refused the call. viem also reports a node's -32603 internal error as a revert, which says nothing about the contract. */
export function isContractRejection(error: unknown): boolean {
  if (!(error instanceof BaseError)) return false;
  if (error.walk(cause => cause instanceof ContractFunctionZeroDataError)) return true;
  const reverted = error.walk(cause => cause instanceof ContractFunctionRevertedError) as ContractFunctionRevertedError | null;
  if (!reverted) return false;
  return !error.walk(cause => cause instanceof InternalRpcError) || !!reverted.data || !!reverted.signature || /revert/i.test(reverted.reason ?? "");
}
export const isRegistryIntent = (intent: Intent) => intent.kind === "link_agent" || intent.kind === "unlink_agent";
export function registryCapability(cfg: Config) {
  const capability = cfg.manifest.agentRegistry;
  if (!capability) throw new WalletError("registry_unavailable", "Agent Registry is not enabled in this network's approved manifest");
  return capability;
}
/** A wallet can open under a manifest that adds the registry before approving it; registry use still requires approval. */
export function assertRegistryApproved(cfg: Config, wallet: { approvedCapabilityManifestId: string }) {
  registryCapability(cfg);
  if (wallet.approvedCapabilityManifestId !== cfg.manifest.manifestId) throw new WalletError("capability_manifest_unapproved", "This wallet has not approved the Agent Registry. Review it with wallet capabilities approve in your local terminal");
}
export function registryPinsMatch(cfg: Config, slot: string | undefined, domain: readonly [string, string, string, bigint, string, ...unknown[]]): boolean {
  const cap = registryCapability(cfg);
  return !!slot && /^0x[0-9a-fA-F]+$/.test(slot) && BigInt(slot) === BigInt(cap.implementation.address)
    && domain[0] === "0x0f" && domain[1] === "Incentiv Agent Registry" && domain[2] === "1"
    && domain[3] === BigInt(cfg.identity.chainId) && sameAddress(domain[4], cap.proxy.address);
}
export async function verifyRegistryDeployment(client: PublicClient, cfg: Config, blockNumber: bigint) {
  const cap = registryCapability(cfg);
  const [proxy, implementation, slot, domain] = await Promise.all([
    client.getCode({ address: cap.proxy.address, blockNumber }), client.getCode({ address: cap.implementation.address, blockNumber }),
    client.getStorageAt({ address: cap.proxy.address, slot: REGISTRY_IMPLEMENTATION_SLOT, blockNumber }),
    client.readContract({ address: cap.proxy.address, abi: agentRegistryAbi, functionName: "eip712Domain", blockNumber }),
  ]);
  if (!proxy || !implementation || keccak256(proxy) !== cap.proxy.codeHash || keccak256(implementation) !== cap.implementation.codeHash || !registryPinsMatch(cfg, slot, domain)) {
    throw new WalletError("registry_verification_failed", "Registry implementation or signing domain changed");
  }
}
export async function registryStatus(client: PublicClient, cfg: Config, agent: Address, parent?: Address, blockNumber?: bigint) {
  const cap = registryCapability(cfg);
  const { read } = getContract({ address: cap.proxy.address, abi: agentRegistryAbi, client });
  const opts = { blockNumber };
  const [agentParent, agentChildren, agentEligible, factoryAllowed, maximum] = await Promise.all([
    read.parentOf([agent], opts), read.agentCount([agent], opts), read.isIncentivAccount([agent], opts),
    read.isAccountFactory([cfg.identity.accountFactory.address], opts), read.maxAgentsPerParent(opts),
  ]);
  const parentState = parent ? await Promise.all([read.isIncentivAccount([parent], opts), read.parentOf([parent], opts), read.agentCount([parent], opts), read.nonces([parent], opts)]) : undefined;
  return { chain_id: cfg.identity.chainId, registry: cap.proxy.address, agent, parent: agentParent as Address,
    agent_is_parent: agentChildren > 0n, agent_eligible: Boolean(agentEligible), factory_allowed: Boolean(factoryAllowed),
    max_agents: maximum.toString(), requested_parent: parent, parent_eligible: parentState ? Boolean(parentState[0]) : undefined,
    parent_is_agent: parentState ? !/^0x0{40}$/i.test(parentState[1]) : undefined,
    parent_agent_count: parentState?.[2].toString(), parent_nonce: parentState?.[3].toString() };
}
/** Why this agent cannot link to any parent; the contract checks a deployed agent itself and the factory only for a new one. */
export function linkBlocker(status: { parent: string; agent_is_parent: boolean; agent_eligible: boolean; factory_allowed: boolean }, deployed: boolean): [code: string, message: string] | undefined {
  if (!/^0x0{40}$/i.test(status.parent)) return ["registry_already_linked", "Agent is already linked; refresh status or unlink first"];
  if (status.agent_is_parent || (deployed ? !status.agent_eligible : !status.factory_allowed)) return ["registry_ineligible", "Account roles or allowed factories do not permit this link"];
}
export function registryCall(cfg: Config, agent: Address, intent: Intent) {
  const cap = registryCapability(cfg);
  if (intent.kind === "unlink_agent") return { to: cap.proxy.address, value: 0n, data: encodeFunctionData({ abi: agentRegistryAbi, functionName: "unlink" }) };
  const a = registryApprovalSchema.parse(intent.registryApproval);
  if (a.chain_id !== cfg.identity.chainId || !sameAddress(a.registry, cap.proxy.address) || !sameAddress(a.agent, agent)
    || !intent.registryParent || !sameAddress(a.parent, intent.registryParent) || sameAddress(a.parent, agent)
    || intent.amount !== "0" || intent.token !== intent.gasToken) throw new WalletError("validation_failed", "Registry approval does not match this wallet, network and parent");
  return { to: cap.proxy.address, value: 0n, data: encodeFunctionData({ abi: agentRegistryAbi, functionName: "link", args: [getAddress(a.parent), agent, BigInt(a.parent_deadline), a.parent_signature as Hex, 0n, "0x"] }) };
}
export async function verifyRegistryIntent(client: PublicClient, cfg: Config, wallet: { account: string }, intent: Intent, state: { block: bigint; timestamp: number; deployed: boolean }) {
  await verifyRegistryDeployment(client, cfg, state.block);
  registryCall(cfg, wallet.account as Address, intent);
  const status = await registryStatus(client, cfg, wallet.account as Address, intent.kind === "unlink_agent" ? undefined : intent.registryParent as Address, state.block);
  if (intent.kind === "unlink_agent") {
    if (/^0x0{40}$/i.test(status.parent)) throw new WalletError("registry_link_changed", "The agent is not linked; refresh status");
    if (!intent.registryParent || !sameAddress(status.parent, intent.registryParent)) throw new WalletError("registry_link_changed", "The agent's parent changed; refresh status before unlinking");
    return;
  }
  const a = intent.registryApproval!;
  const localNow = Math.floor(Date.now() / 1000);
  if (state.timestamp < localNow - 60 || state.timestamp > localNow + 30) throw new WalletError("registry_rpc_unavailable", "Registry RPC block is stale or in the future, or the local clock is wrong; retry this request");
  const now = Math.max(localNow, state.timestamp);
  if (Number(a.parent_deadline) <= now + 10) throw new WalletError("registry_approval_expired", "Portal approval expired or is too close to expiry; obtain a fresh approval");
  const blocked = linkBlocker(status, state.deployed);
  if (blocked) throw new WalletError(...blocked);
  if (status.parent_is_agent || !status.parent_eligible) throw new WalletError("registry_ineligible", "Account roles or allowed factories do not permit this link");
  if (BigInt(status.parent_agent_count!) >= BigInt(status.max_agents)) throw new WalletError("registry_limit_reached", "Parent has reached its agent limit; unlink an agent in Portal first");
  if (status.parent_nonce !== a.parent_nonce) throw new WalletError("registry_approval_stale", "Parent nonce changed; obtain a fresh Portal approval");
  const cap = registryCapability(cfg);
  const digest = await client.readContract({ address: cap.proxy.address, abi: agentRegistryAbi, functionName: "parentLinkDigest", args: [a.parent as Address, wallet.account as Address, BigInt(a.parent_deadline)], blockNumber: state.block });
  const magic = await client.readContract({ address: a.parent as Address, abi: accountSignatureAbi, functionName: "isValidSignature", args: [digest, a.parent_signature as Hex], blockNumber: state.block }).catch((error: unknown) => {
    // A rejecting or codeless parent is an invalid signature; an RPC failure says nothing about it.
    if (isContractRejection(error)) return "0x";
    throw error;
  });
  if (magic !== "0x1626ba7e") throw new WalletError("registry_approval_invalid", "Parent signature is invalid; obtain a fresh Portal approval");
}
// Only inspect the log interval belonging to this operation within an EntryPoint bundle.
export function hasRegistryEvent(cfg: Config, intent: Intent, agent: string, logs: { address: string; data: Hex; topics: readonly Hex[] }[]) {
  const event = intent.kind === "link_agent" ? "AgentLinked" : "AgentUnlinked";
  // A receipt may be reconciled under a manifest without the registry; report the event as missing rather than blocking the wallet.
  const proxy = cfg.manifest.agentRegistry?.proxy.address;
  return !!proxy && logs.some(log => {
    if (!sameAddress(log.address, proxy)) return false;
    try {
      const decoded = decodeEventLog({ abi: agentRegistryAbi, data: log.data, topics: log.topics as [Hex, ...Hex[]], strict: true });
      return decoded.eventName === event && "parent" in decoded.args && sameAddress(decoded.args.parent, intent.registryParent!) && sameAddress(decoded.args.agent, agent)
        && (decoded.eventName !== "AgentUnlinked" || sameAddress(decoded.args.by, agent));
    } catch { return false; }
  });
}
