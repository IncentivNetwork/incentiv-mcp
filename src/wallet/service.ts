import { isRegistryIntent, registryCapability, linkBlocker, parentBlocker } from "../agent-registry.js";
import { getAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { type Hex } from "viem";
import { z } from "zod";
import { type Config } from "../config.js";
import { Ctx } from "../context.js";
import { NetworkError } from "../network.js";
import { userOpToJson } from "../userop.js";
import { publicWallet, unlockWallet, WalletError } from "./keystore.js";
import { localWalletStore, type WalletSession, type WalletStore } from "./store.js";
import { Journal, digest, intentSchema, ownsNonce, terminal, type Intent, type OperationRecord } from "./journal.js";
import { addSpend, authorize, limitsSchema, newAdministration, policyViolations, registryParentAllowed, type Limits, type Spend } from "./policy.js";
import { MIN_SWAP_REMAINING_SECONDS, SWAP_DEADLINE_SECONDS, WalletChain, isTransportFailure } from "./chain.js";
import { validateOperation } from "./validate.js";

// Source-controlled local candidate signing, explicitly authorized for acceptance testing.
// Every request still needs the authenticated wallet policy and all transaction checks.
// This is NOT publication approval: publication is a separate, manual decision.
// There is no environment-variable or MCP-argument override.
export const WALLET_CANDIDATE_SIGNING_ENABLED = true;

export class WalletService {
  constructor(readonly ctx: Ctx, readonly store: WalletStore = localWalletStore(ctx.config), readonly chain: WalletChain = new WalletChain(ctx), private readonly signingEnabled = WALLET_CANDIDATE_SIGNING_ENABLED) {}
  create() { return this.store.createOrLoad(); }
  private async enabled(s: WalletSession): Promise<Limits> {
    if (!s.envelope.policy.configured) throw new WalletError("policy_not_configured", "Run incentiv-mcp setup in your local terminal");
    if (!s.envelope.policy.enabled || await s.disabled()) throw new WalletError("wallet_locked", "Wallet is disabled; local administration authorization is required");
    return s.envelope.policy.limits;
  }
  private liveTestApproved(s: WalletSession, r?: OperationRecord): boolean {
    const a = r?.approval;
    return !!r && !!a?.liveTest && !!r.operation && r.intent.kind === "transfer" && r.intent.gasToken === "native"
      && a.liveTest.requestId === r.requestId && a.liveTest.policyDigest === digest(s.envelope.policy)
      && a.intentHash === r.intentHash && r.intentHash === digest(r.intent) && a.userOpHash === r.userOpHash
      && a.operationDigest === digest({ ...r.operation, signature: "0x" }) && a.expiresAt > Date.now();
  }
  private async canSubmit(s: WalletSession, r?: OperationRecord): Promise<void> {
    await s.assertOwned(); await this.enabled(s);
    if (!this.signingEnabled && !this.liveTestApproved(s, r)) throw new WalletError("wallet_release_unreviewed", "Candidate signing is disabled; a funded transfer needs local approval of this exact operation");
  }
  private approved(s: WalletSession, r: OperationRecord): boolean {
    const a = r.approval;
    return !!a && !!r.operation && a.policyDigest === digest(s.envelope.policy)
      && a.intentHash === digest(r.intent) && a.userOpHash === r.userOpHash
      && a.operationDigest === digest({ ...r.operation, signature: "0x" }) && a.expiresAt > Date.now();
  }
  private async revalidate(s: WalletSession, journal: Journal, r: OperationRecord): Promise<void> {
    await this.canSubmit(s, r);
    const limits = await this.enabled(s), state = await this.chain.state(s.envelope);
    if (!r.operation || !r.userOpHash || state.nonce !== BigInt(r.nonce!)) throw new WalletError("operation_pending", "Operation nonce changed; reconcile before retrying");
    const validated = validateOperation(this.ctx.config, s.envelope, r.intent, { ...r.operation, signature: "0x" }, { nonce: state.nonce, deployed: state.deployed, hash: r.userOpHash, deadline: r.deadline });
    if (digest(validated.spend) !== digest(r.reservation)) throw new WalletError("wallet_recovery_required", "Operation reservation does not match the signed spend");
    const balances = await this.chain.balances(s.envelope, this.balanceTokens(limits)), used = journal.used();
    if (ownsNonce(r.status)) for (const [token, amount] of Object.entries(r.reservation)) addSpend(used, token, -BigInt(amount));
    const violations = policyViolations(limits, { ...this.registryPolicy(r.intent), token: r.intent.token, tokenOut: r.intent.tokenOut, amount: r.intent.amount, to: r.intent.to, swap: r.intent.kind === "swap", slippage: r.intent.slippageBps, spend: validated.spend, used, balances, gasCost: validated.gasCost, fee: validated.op.maxFeePerGas, gasUnits: validated.gasUnits, gasToken: r.intent.gasToken, gasCharge: validated.gasCharge, calls: validated.calls });
    if (violations.includes("exposure_limit") || (violations.length && (!this.approved(s, r) || r.approval?.liveTest))) throw new WalletError("policy_denied", "Current policy does not permit this signed operation; reservation preserved");
    if (r.approval && !this.approved(s, r)) throw new WalletError("approval_required", "Exact-operation approval expired or policy changed; reservation preserved");
    if (Object.entries(validated.spend).some(([token, amount]) => BigInt(balances[token] ?? "0") < BigInt(amount))) throw new WalletError("policy_denied", "Balance cannot cover input plus maximum gas");
    if (state.fees.baseFeePerGas > validated.op.maxFeePerGas) throw new WalletError("validation_failed", "Gas fee no longer covers the current base fee");
    if (isRegistryIntent(r.intent)) await this.chain.verifyRegistry(s.envelope, r.intent, state);
    if (r.intent.kind === "swap") await this.chain.verifySwap(s.envelope, r.intent, limits, state);
    await this.chain.simulate(validated);
    await this.canSubmit(s, r);
    if (r.deadline && r.deadline <= Math.floor(Date.now() / 1000) + MIN_SWAP_REMAINING_SECONDS) throw new WalletError("operation_pending", "Operation deadline is too close; reconcile or review a same-nonce replacement");
  }
  private async reconcile(journal: Journal): Promise<void> {
    for (const r of journal.data.records.filter(r => ownsNonce(r.status))) {
      if (r.status === "signed") continue; // No network submission was started; exact bytes remain retryable.
      if (r.status === "submitting") await journal.transition(r, "submission_unknown");
      try {
        const receipt = await this.chain.receipt(r);
        if (!receipt && r.replacement?.signed) {
          const replaced = await this.chain.receipt({ ...r, operation: r.replacement.operation, userOpHash: r.replacement.userOpHash });
          if (replaced) {
            const gasToken = r.replacement!.gasToken ?? "native";
            r.consumed = gasToken === "native" ? { native: replaced.actualGasCost.toString() } : { [gasToken]: r.replacement!.gasCharge! }; r.consumedAt = Date.now(); r.transactionHash = replaced.transactionHash;
            // A mined replacement consumes the nonce even if its execution reverted.
            await journal.transition(r, "superseded"); continue;
          }
        }
        if (!receipt) { if (r.status === "submitted") await journal.transition(r, "submission_unknown"); continue; }
        const spend: Spend = {};
        if (receipt.success) addSpend(spend, r.intent.token, BigInt(r.intent.amount));
        // Token-paymaster refunds are not inferred from an untrusted relay. Retain the
        // full authorized token payment conservatively, including reverted operations.
        const input = r.intent.token === r.intent.gasToken ? BigInt(r.intent.amount) : 0n;
        // If the original wins, release the unused replacement's gas reservation.
        const replacementGas = r.replacement?.signed && (r.replacement.gasToken ?? "native") === r.intent.gasToken
          ? BigInt(r.replacement.gasCharge ?? r.replacement.maxGasCost) : 0n;
        const gas = r.intent.gasToken === "native" ? receipt.actualGasCost : BigInt(r.reservation[r.intent.gasToken] ?? "0") - input - replacementGas;
        if (gas < 0n) throw new WalletError("wallet_recovery_required", "Invalid persisted gas reservation");
        addSpend(spend, r.intent.gasToken, gas);
        if (receipt.registryError) r.lastError = receipt.registryError;
        r.consumed = spend; r.consumedAt = Date.now(); r.transactionHash = receipt.transactionHash;
        await journal.transition(r, receipt.success ? "confirmed" : "reverted");
      } catch (error) {
        if (error instanceof WalletError) throw error;
        if (r.status === "submitted") await journal.transition(r, "submission_unknown");
      }
    }
  }
  private async submit(s: WalletSession, journal: Journal, r: OperationRecord): Promise<void> {
    await this.canSubmit(s, r);
    if (!r.operation || !r.userOpHash) throw new WalletError("wallet_recovery_required", "Signed operation is missing");
    if (r.deadline && r.deadline <= Math.floor(Date.now() / 1000)) throw new WalletError("operation_pending", "Signed operation deadline expired; review a same-nonce replacement with wallet operation resolve --replace");
    await this.revalidate(s, journal, r);
    // Reconcile happened under the same cross-process lock before this retry.
    r.attempts++;
    await journal.transition(r, "submitting");
    await this.canSubmit(s, r);
    try {
      const returned = await this.chain.relay(r.operation, () => this.revalidate(s, journal, r));
      if (returned !== r.userOpHash) throw new Error();
    } catch {
      r.lastError = "submission_unknown";
      await journal.transition(r, "submission_unknown"); return;
    }
    await journal.transition(r, "submitted");
  }
  async send(kind: Intent["kind"], args: Record<string, unknown>, prepareOnly = false) {
    const requestId = z.string().uuid().parse(args.request_id).toLowerCase();
    let response = await this.store.session(async s => {
      const limits = await this.enabled(s);
      const journal = await Journal.open(s);
      const intent = intentSchema.parse(await this.chain.normalize(kind, args));
      let r = journal.data.records.find(r => r.requestId === requestId);
      if (r && r.intentHash !== digest(intent)) throw new WalletError("idempotency_conflict", "This request ID is permanently bound to a different intent");
      await this.reconcile(journal);
      if (r && terminal(r.status)) return result(r);
      if (r && ownsNonce(r.status)) {
        if (prepareOnly) return result(r);
        if (r.status === "superseding") await this.submitReplacement(s, journal, r);
        else if (r.status === "signed" || r.status === "submission_unknown") await this.submit(s, journal, r);
        if (args.wait_for_confirmation === true) await this.reconcile(journal);
        return result(r);
      }
      if (journal.data.records.some(r => ownsNonce(r.status))) throw new WalletError("operation_pending", "An unresolved operation owns the account nonce; reconcile it first");
      // Rejected new registry requests must not consume journal capacity. An existing record is checked below, where a failure closes it.
      const existing = !!r;
      if (!existing && intent.kind === "link_agent") {
        // Reusing one Portal approval under new request IDs must not be able to fill the journal,
        // so attempts are counted per approval rather than per intent (which varies with gas token).
        const approval = digest(intent.registryApproval);
        const attempts = journal.data.records.filter(o => o.intent.kind === "link_agent" && digest(o.intent.registryApproval) === approval);
        const open = attempts.find(o => !terminal(o.status));
        if (open) throw new WalletError("operation_pending", `Request ${open.requestId} already holds this Portal approval; retry with that request ID`);
        if (attempts.length >= MAX_LINK_ATTEMPTS) throw new WalletError("policy_denied", "This Portal approval has been tried too many times; obtain a fresh approval");
      }
      if (!existing && isRegistryIntent(intent)) await this.chain.verifyRegistry(s.envelope, intent);
      if (r?.status === "approval_required") {
        if (TEMPORARY_ERRORS.includes(r.lastError ?? "")) delete r.lastError;
        if (r.approval && r.approval.expiresAt <= Date.now()) { await journal.transition(r, "expired"); return result(r); }
        await journal.transition(r, "preparing");
      }
      r ??= await journal.create(requestId, intent);
      try {
        if (existing && isRegistryIntent(intent)) await this.chain.verifyRegistry(s.envelope, intent);
        const state = await this.chain.state(s.envelope);
        const balances = await this.chain.balances(s.envelope, this.balanceTokens(limits));
        const used = journal.used();
        // First policy evaluation precedes building; violations may build an unsigned review candidate.
        const initialSpend: Spend = {}; addSpend(initialSpend, intent.token, BigInt(intent.amount));
        const initial = policyViolations(limits, { ...this.registryPolicy(intent), token: intent.token, tokenOut: intent.tokenOut, amount: intent.amount, to: intent.to, swap: kind === "swap", slippage: intent.slippageBps, spend: initialSpend, used, balances, gasCost: 0n, fee: 0n, gasUnits: 0n, gasToken: intent.gasToken, gasCharge: 0n, calls: [] });
        if (kind === "swap") await this.chain.verifySwap(s.envelope, intent, limits, state);
        if (r.approval && !this.approved(s, r)) delete r.approval;
        if (!r.approval) {
          if (kind === "link_agent") r.deadline = Number(intent.registryApproval!.parent_deadline);
          if (kind === "swap") r.deadline = Math.min(Math.floor(Date.now() / 1000), state.timestamp) + SWAP_DEADLINE_SECONDS;
          const built = await this.chain.build(s.envelope, intent, state, r.deadline);
          r.operation = userOpToJson(built.op); r.userOpHash = built.userOpHash; r.nonce = built.op.nonce.toString();
        }
        const validated = validateOperation(this.ctx.config, s.envelope, intent, r.operation!, { nonce: state.nonce, deployed: state.deployed, hash: r.userOpHash!, deadline: r.deadline });
        const violations = [...new Set([...initial, ...policyViolations(limits, { ...this.registryPolicy(intent), token: intent.token, tokenOut: intent.tokenOut, amount: intent.amount, to: intent.to, swap: kind === "swap", slippage: intent.slippageBps, spend: validated.spend, used, balances, gasCost: validated.gasCost, fee: validated.op.maxFeePerGas, gasUnits: validated.gasUnits, gasToken: intent.gasToken, gasCharge: validated.gasCharge, calls: validated.calls })])];
        for (const [token, amount] of Object.entries(validated.spend)) if (BigInt(balances[token] ?? "0") < BigInt(amount)) throw new WalletError("policy_denied", "Insufficient input balance plus maximum gas payment");
        r.reservation = validated.spend;
        await this.chain.simulate(validated);
        // Exposure must be addressed by configuring limits or reducing wallet funding.
        if (violations.includes("exposure_limit")) delete r.approval;
        if (violations.length && (!r.approval || r.approval.liveTest)) {
          delete r.approval;
          r.reasons = violations; await journal.transition(r, "approval_required"); return result(r);
        }
        if (r.approval && (r.approval.intentHash !== r.intentHash || r.approval.userOpHash !== validated.hash || r.approval.operationDigest !== digest(r.operation) || r.approval.expiresAt <= Date.now())) throw new WalletError("approval_required", "Approval no longer matches the exact operation");
        // Cross-check nonce again immediately before the signature, after asynchronous simulation.
        const fresh = await this.chain.state(s.envelope);
        if (fresh.nonce !== state.nonce || fresh.deployed !== state.deployed) throw new WalletError("validation_failed", "Account state changed during build; use a new request ID after review");
        if (fresh.fees.baseFeePerGas > validated.op.maxFeePerGas) throw new WalletError("validation_failed", "Gas fee no longer covers the current base fee");
        if (isRegistryIntent(intent)) await this.chain.verifyRegistry(s.envelope, intent, fresh);
        if (kind === "swap") await this.chain.verifySwap(s.envelope, intent, limits, fresh);
        const freshBalances = await this.chain.balances(s.envelope, this.balanceTokens(limits));
        const finalViolations = policyViolations(limits, { ...this.registryPolicy(intent), token: intent.token, tokenOut: intent.tokenOut, amount: intent.amount, to: intent.to, swap: kind === "swap", slippage: intent.slippageBps, spend: validated.spend, used: journal.used(), balances: freshBalances, gasCost: validated.gasCost, fee: validated.op.maxFeePerGas, gasUnits: validated.gasUnits, gasToken: intent.gasToken, gasCharge: validated.gasCharge, calls: validated.calls });
        if (finalViolations.includes("exposure_limit") || (finalViolations.length && (!r.approval || r.approval.liveTest))) {
          r.reasons = finalViolations; delete r.approval; await journal.transition(r, "approval_required"); return result(r);
        }
        for (const [token, amount] of Object.entries(validated.spend)) if (BigInt(freshBalances[token] ?? "0") < BigInt(amount)) throw new WalletError("policy_denied", "Balance changed before signing");
        if (prepareOnly || (!this.signingEnabled && !this.liveTestApproved(s, r))) {
          r.reasons = ["release_test_approval_required"]; await journal.transition(r, "approval_required"); return result(r);
        }
        await this.canSubmit(s, r);
        if (r.approval && r.approval.expiresAt <= Date.now()) throw new WalletError("approval_required", "Exact-operation approval expired before signing");
        if (r.deadline && r.deadline <= Math.floor(Date.now() / 1000) + MIN_SWAP_REMAINING_SECONDS) throw new WalletError("validation_failed", "Operation deadline is too close");
        const privateKey = unlockWallet(this.ctx.config, s.envelope, s.wrappingKey);
        try {
          // viem requires a hex string; V8 cannot guarantee zeroization of that temporary.
          r.operation!.signature = await privateKeyToAccount(`0x${privateKey.toString("hex")}`).signMessage({ message: { raw: validated.hash } });
        } finally { privateKey.fill(0); }
        await this.canSubmit(s, r);
        await journal.transition(r, "signed"); // fsync completes before any submission.
      } catch (error) {
        // An RPC outage says nothing about the request, so its ID and any local approval stay usable.
        const failure = error instanceof WalletError ? error : isTransportFailure(error) ? new WalletError("rpc_unavailable", "Could not read chain state from RPC; retry this request") : undefined;
        if (r.status === "preparing" && TEMPORARY_ERRORS.includes(failure?.code ?? "")) { r.lastError = failure!.code; await journal.transition(r, "approval_required"); }
        else if (r.status === "preparing") { r.lastError = failure?.code ?? "validation_failed"; await journal.transition(r, "failed"); }
        if (failure) throw failure;
        throw new WalletError("validation_failed", "Local operation preparation failed");
      }
      await this.submit(s, journal, r);
      if (args.wait_for_confirmation === true) await this.reconcile(journal);
      return result(r);
    });
    if (!prepareOnly && args.wait_for_confirmation === true) {
      const deadline = Date.now() + 30_000;
      while (ownsNonce(response.status) && Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        response = await this.operation(requestId);
      }
    }
    return response;
  }
  private registryPolicy(intent: Intent) {
    return isRegistryIntent(intent) ? { registryKind: intent.kind as "link_agent" | "unlink_agent", registryParent: intent.registryParent } : {};
  }
  async registryStatus(parent?: string) {
    return this.store.session(s => this.chain.registryStatus(s.envelope, parent ? getAddress(parent) : undefined));
  }
  /**
   * The Portal URL that asks the user to connect this agent. With `parent`, the agent also signs its own
   * AgentLink consent to that parent, so Portal can submit the link from the parent's account once the
   * user trusts this agent. That needs the same authenticated local policy as link_agent: the parent must
   * be allowed, and the wallet enabled for signing. The signature names this one parent, which still has
   * to send the link itself, so it gives nobody else a way to link this agent.
   */
  async prepareAgentLink(parent?: string) {
    return this.store.session(async s => {
      const cap = registryCapability(this.ctx.config);
      const requested = parent ? getAddress(parent) : undefined;
      const status = await this.chain.registryStatus(s.envelope, requested);
      const blocked = linkBlocker(status, status.deployed) ?? (requested ? parentBlocker(status, requested) : undefined);
      if (blocked) return { ...status, link_blocked: blocked[0], next_action: `${blocked[1]}. Do not ask the user to sign in Portal.` };
      const url = new URL(cap.portalUrl);
      url.searchParams.set("agent", s.envelope.account);
      url.searchParams.set("chain_id", String(this.ctx.config.identity.chainId));
      url.searchParams.set("registry", cap.proxy.address);
      const approvalFlow = "Open Portal, review and sign the connection, then pass its approval JSON to link_agent with a new request UUID. Never sign a supplied digest.";
      if (!requested) return { ...status, portal_url: url.href, next_action: approvalFlow };
      // The registry checks a signature through the agent account's ERC-1271, so an undeployed agent cannot consent this way.
      if (!status.deployed) return { ...status, portal_url: url.href, agent_signed: false, next_action: `This agent is not deployed yet, so Portal cannot submit the link. ${approvalFlow}` };
      const limits = await this.enabled(s);
      if (!registryParentAllowed(limits, requested)) return { ...status, link_blocked: "registry_parent_not_allowed", next_action: "Local wallet policy does not allow this parent. Add it with incentiv-mcp setup in your local terminal, then call prepare_agent_link again. Do not ask the user to sign in Portal." };
      if (limits.expiresAt && Date.now() >= limits.expiresAt) return { ...status, link_blocked: "policy_expired", next_action: "Local wallet policy expired. Renew it with incentiv-mcp setup in your local terminal. Do not ask the user to sign in Portal." };
      await this.canSubmit(s);
      const consent = await this.chain.agentLinkDigest(s.envelope, requested);
      const privateKey = unlockWallet(this.ctx.config, s.envelope, s.wrappingKey);
      let signature: Hex;
      try {
        // The account checks its owner's EIP-191 signature over the digest bytes, as for operations.
        signature = await privateKeyToAccount(`0x${privateKey.toString("hex")}`).signMessage({ message: { raw: consent.digest } });
      } finally { privateKey.fill(0); }
      await this.chain.verifyAgentLinkSignature(s.envelope, consent.digest, signature, consent.block);
      url.searchParams.set("parent", requested);
      url.searchParams.set("agent_nonce", consent.nonce.toString());
      url.searchParams.set("agent_deadline", consent.deadline.toString());
      url.searchParams.set("agent_signature", signature);
      return { ...status, portal_url: url.href, agent_signed: true, agent_link: { parent: requested, agent_nonce: consent.nonce.toString(), agent_deadline: consent.deadline.toString() },
        next_action: "Give this URL to the user. In Portal they trust this agent, then submit the connection from their account and pay its fee. Do not call link_agent. Check get_agent_registry_status afterwards. The request expires at agent_deadline, or earlier if this agent's registry nonce changes." };
    });
  }
  private balanceTokens(limits: Limits): string[] {
    return ["native", ...Object.keys(limits.tokens), ...Object.values(this.ctx.config.manifest.canonicalTokens).map(p => p.address), this.ctx.config.manifest.contracts.wcent.address];
  }
  async get() {
    return this.store.session(async s => {
      const journal = await Journal.open(s, !s.envelope.policy.configured);
      await this.reconcile(journal);
      const state = await this.chain.state(s.envelope), policy = s.envelope.policy;
      const balances = await this.chain.balances(s.envelope, policy.configured ? this.balanceTokens(policy.limits) : ["native"]);
      const reserved: Spend = {};
      for (const r of journal.data.records.filter(r => ownsNonce(r.status))) for (const [token, amount] of Object.entries(r.reservation)) addSpend(reserved, token, BigInt(amount));
      const spendable = Object.fromEntries(Object.entries(balances).map(([token, amount]) => [token, (BigInt(amount) > BigInt(reserved[token] ?? "0") ? BigInt(amount) - BigInt(reserved[token] ?? "0") : 0n).toString()]));
      const disabled = await s.disabled() || !policy.enabled;
      const gasDeposit = await this.chain.gasDeposit(s.envelope);
      // release_approved is retained as a legacy alias for the local signing gate.
      // It never attests to public release review or npm publication.
      return { ...publicWallet(s.envelope), reason: !policy.configured ? "policy_not_configured" : disabled ? "wallet_disabled" : "operation_required_for_gas_estimate", deployed: state.deployed, balances, entrypoint_gas_deposit_wei: gasDeposit, pending_reservations: reserved, spendable_before_new_gas: spendable, gas_options: policy.configured ? Object.keys(policy.limits.tokens) : [], estimated_max_gas_payment: null, pending_operations: journal.data.records.filter(r => !terminal(r.status)).map(result), candidate_signing_enabled: this.signingEnabled, release_approved: this.signingEnabled, next_action: !policy.configured ? "Run incentiv-mcp setup in your own terminal" : disabled ? "Run incentiv-mcp setup to review permissions, back up and re-enable" : "Provide a transfer or swap intent to check exact transfer-plus-gas readiness" };
    });
  }
  async operation(id: string) {
    return this.store.session(async s => {
      const journal = await Journal.open(s); await this.reconcile(journal);
      const r = journal.data.records.find(r => r.requestId === id.toLowerCase() || r.userOpHash === id.toLowerCase());
      if (!r) throw new WalletError("operation_not_found", "No journaled operation matches this ID or hash");
      return result(r);
    });
  }
  async review(id?: string) {
    return this.store.session(async s => {
      const journal = await Journal.open(s, !s.envelope.policy.configured); await this.reconcile(journal);
      return { wallet: publicWallet(s.envelope), records: journal.data.records.filter(r => id ? r.requestId === id : !terminal(r.status)) };
    });
  }
  async configure(limits: Limits, passphrase: Buffer, acknowledgedRestored: boolean, reviewedDigest: Hex, enabled = true) {
    limitsSchema.parse(limits);
    await this.store.session(async s => {
      const old = s.envelope.policy;
      if (old.configured) await authorize(old, passphrase);
      const journal = await Journal.open(s, !old.configured); await this.reconcile(journal);
      if (digest(journal.data.records.filter(r => !terminal(r.status))) !== reviewedDigest) throw new WalletError("approval_required", "Pending operations changed; review them again");
      if (enabled && old.configured && old.restored && !acknowledgedRestored) throw new WalletError("policy_denied", "Confirm the source wallet is disabled or destroyed before re-enabling this restored wallet");
      await this.chain.state(s.envelope); // Reconcile the live nonce before re-enable.
      await journal.save();
      await s.savePolicy({ schemaVersion: 1, configured: true, enabled, limits, administration: old.configured ? old.administration : await newAdministration(passphrase), ...(enabled ? { restored: false } : old.configured && old.restored !== undefined ? { restored: old.restored } : {}) });
      if (enabled) await s.clearDisabled();
    });
  }
  async approve(id: string, passphrase: Buffer, reviewedDigest: Hex, liveTest = false) {
    await this.store.session(async s => {
      await authorize(s.envelope.policy, passphrase); const limits = await this.enabled(s);
      if (!liveTest && !this.signingEnabled) throw new WalletError("wallet_release_unreviewed", "Use wallet test-transfer for an explicitly reviewed funded test");
      const journal = await Journal.open(s); await this.reconcile(journal);
      const r = journal.data.records.find(r => r.requestId === id);
      const retry = liveTest && !!r?.approval?.liveTest && (r.status === "signed" || r.status === "submission_unknown");
      if (!r || (r.status !== "approval_required" && !retry) || !r.operation || !r.userOpHash || digest(r) !== reviewedDigest) throw new WalletError("approval_required", "Review the current locally validated operation first");
      assertNeedsApproval(r);
      if (r.reasons?.includes("exposure_limit")) throw new WalletError("policy_denied", "Change exposure limits interactively or reduce wallet funding first");
      if (liveTest && (r.intent.kind !== "transfer" || r.intent.gasToken !== "native" || r.replacement)) throw new WalletError("policy_denied", "Funded test approval only permits a transfer with native gas and no replacement");
      const state = await this.chain.state(s.envelope);
      const unsigned = { ...r.operation, signature: "0x" };
      const validated = validateOperation(this.ctx.config, s.envelope, r.intent, unsigned, { nonce: state.nonce, deployed: state.deployed, hash: r.userOpHash, deadline: r.deadline });
      if (isRegistryIntent(r.intent)) await this.chain.verifyRegistry(s.envelope, r.intent, state);
      if (r.intent.kind === "swap") await this.chain.verifySwap(s.envelope, r.intent, limits, state);
      if (liveTest) {
        const balances = await this.chain.balances(s.envelope, this.balanceTokens(limits)), used = journal.used();
        // An exact retry already owns this reservation; do not count it twice.
        if (ownsNonce(r.status)) for (const [token, amount] of Object.entries(r.reservation)) addSpend(used, token, -BigInt(amount));
        const violations = policyViolations(limits, { ...this.registryPolicy(r.intent), token: r.intent.token, amount: r.intent.amount, to: r.intent.to, swap: false, slippage: 0, spend: validated.spend, used, balances, gasCost: validated.gasCost, fee: validated.op.maxFeePerGas, gasUnits: validated.gasUnits, gasToken: r.intent.gasToken, gasCharge: validated.gasCharge, calls: validated.calls });
        if (violations.length || Object.entries(validated.spend).some(([token, amount]) => BigInt(balances[token] ?? "0") < BigInt(amount))) throw new WalletError("policy_denied", "A funded test must satisfy every policy and balance limit; it cannot approve exceptions");
        if (state.fees.baseFeePerGas > validated.op.maxFeePerGas) throw new WalletError("validation_failed", "Reviewed gas fee no longer covers the current base fee");
      }
      await this.chain.simulate(validated);
      r.approval = { intentHash: r.intentHash, userOpHash: r.userOpHash, operationDigest: digest(unsigned), policyDigest: digest(s.envelope.policy), expiresAt: Math.min(Date.now() + 300_000, r.deadline ? (r.deadline - MIN_SWAP_REMAINING_SECONDS) * 1000 : Infinity), ...(liveTest ? { liveTest: { requestId: r.requestId, policyDigest: digest(s.envelope.policy) } } : {}) };
      r.sequence = ++journal.data.sequence; await journal.save();
    });
  }
  async resolve(id: string, passphrase: Buffer) {
    return this.store.session(async s => {
      await authorize(s.envelope.policy, passphrase);
      const journal = await Journal.open(s); await this.reconcile(journal);
      const r = journal.data.records.find(r => r.requestId === id);
      if (!r) throw new WalletError("operation_not_found", "Unknown request ID");
      if (r.status === "superseding") await this.submitReplacement(s, journal, r);
      else if (r.status === "signed" || r.status === "submission_unknown") await this.submit(s, journal, r);
      return result(r);
    });
  }

  async reviewReplacement(id: string, nativeGas = false) {
    return this.store.session(async s => {
      await this.enabled(s);
      const journal = await Journal.open(s); await this.reconcile(journal);
      const r = journal.data.records.find(r => r.requestId === id);
      if (!r || !ownsNonce(r.status) || r.replacement?.signed) throw new WalletError("operation_pending", "Replacement requires an unresolved original operation without a signed replacement");
      const state = await this.chain.state(s.envelope);
      // Native gas clears the nonce when the token balance or paymaster cannot.
      const gasToken = nativeGas ? "native" : r.intent.gasToken;
      const built = await this.replacementStep(gasToken, () => this.chain.buildReplacement(s.envelope, r, state, gasToken));
      const wire = userOpToJson(built.op);
      const validated = validateOperation(this.ctx.config, s.envelope, this.replacementIntent(s, gasToken), wire, { nonce: BigInt(r.nonce!), deployed: state.deployed, hash: built.userOpHash });
      await this.replacementStep(gasToken, () => this.chain.simulate(validated));
      r.replacement = { operation: wire, userOpHash: validated.hash, maxGasCost: validated.gasCost.toString(), ...(gasToken !== "native" ? { gasToken, gasCharge: validated.gasCharge.toString() } : {}), signed: false, expiresAt: Date.now() + 300_000 };
      r.sequence = ++journal.data.sequence; await journal.save();
      return { wallet: publicWallet(s.envelope), records: [structuredClone(r)] };
    });
  }
  /** A stuck nonce is urgent: say what to do next rather than suggesting storage damage. */
  private async replacementStep<T>(gasToken: string, step: () => Promise<T> | T): Promise<T> {
    try { return await step(); } catch (error) {
      // Only gas payment problems can be cleared by paying in native gas; other errors keep their own guidance.
      if (error instanceof WalletError) throw GAS_FIXABLE_ERRORS.includes(error.code) ? new WalletError(error.code, `${error.message.slice(error.code.length + 2)}.${nativeGasHint(this.ctx.config, gasToken)}`) : error;
      if (error instanceof NetworkError) throw error;
      throw new WalletError("validation_failed", `Could not prepare this replacement; retry.${nativeGasHint(this.ctx.config, gasToken)}`);
    }
  }
  private replacementIntent(s: WalletSession, gasToken = "native"): Intent {
    return { intentSchemaVersion: 1, kind: "transfer", token: "native", amount: "0", gasToken, to: s.envelope.account, slippageBps: 0, feeTier: 3000 };
  }
  async replace(id: string, passphrase: Buffer, reviewedDigest: Hex) {
    return this.store.session(async s => {
      await authorize(s.envelope.policy, passphrase); await this.canSubmit(s);
      const journal = await Journal.open(s); await this.reconcile(journal);
      const r = journal.data.records.find(r => r.requestId === id);
      if (!r || !ownsNonce(r.status) || !r.replacement || r.replacement.signed || r.replacement.expiresAt <= Date.now() || digest(r) !== reviewedDigest) throw new WalletError("approval_required", "Replacement changed or expired; review it again");
      const state = await this.chain.state(s.envelope);
      if (state.nonce !== BigInt(r.nonce!)) throw new WalletError("operation_pending", "Original nonce has already moved; reconcile before replacing");
      const replacement = r.replacement;
      const validated = validateOperation(this.ctx.config, s.envelope, this.replacementIntent(s, replacement.gasToken ?? "native"), replacement.operation, { nonce: state.nonce, deployed: state.deployed, hash: replacement.userOpHash });
      if (validated.gasCost.toString() !== replacement.maxGasCost) throw new WalletError("validation_failed", "Replacement gas ceiling changed");
      const gasToken = replacement.gasToken ?? "native";
      if (gasToken !== "native" && validated.gasCharge.toString() !== replacement.gasCharge) throw new WalletError("validation_failed", "Replacement token gas payment changed");
      await this.replacementStep(gasToken, () => this.chain.simulate(validated));
      const balances = await this.chain.balances(s.envelope, [gasToken]);
      if (BigInt(balances[gasToken] ?? "0") < validated.gasCharge) throw new WalletError("policy_denied", `Balance cannot cover the reviewed replacement gas payment.${nativeGasHint(this.ctx.config, gasToken)}`);
      await this.canSubmit(s);
      if (replacement.expiresAt <= Date.now()) throw new WalletError("approval_required", "Replacement review expired before signing");
      const key = unlockWallet(this.ctx.config, s.envelope, s.wrappingKey);
      try { replacement.operation.signature = await privateKeyToAccount(`0x${key.toString("hex")}`).signMessage({ message: { raw: validated.hash } }); }
      finally { key.fill(0); }
      replacement.signed = true;
      // Keep the original reservation as well: either signed operation might win.
      addSpend(r.reservation, gasToken, validated.gasCharge);
      await journal.transition(r, "superseding");
      await this.submitReplacement(s, journal, r);
      return result(r);
    });
  }
  private async submitReplacement(s: WalletSession, journal: Journal, r: OperationRecord) {
    await this.canSubmit(s);
    if (!r.replacement?.signed || r.status !== "superseding") throw new WalletError("wallet_recovery_required", "Missing signed replacement");
    r.attempts++; r.sequence = ++journal.data.sequence; await journal.save();
    try {
      const hash = await this.chain.relay(r.replacement.operation, () => this.canSubmit(s));
      if (hash !== r.replacement.userOpHash) throw new Error();
      delete r.lastError;
    } catch { r.lastError = "submission_unknown"; }
    r.sequence = ++journal.data.sequence; await journal.save();
  }
}
const MAX_LINK_ATTEMPTS = 8;
const TEMPORARY_ERRORS = ["registry_rpc_unavailable", "rpc_unavailable"];
const GAS_FIXABLE_ERRORS = ["policy_denied", "simulation_failed", "validation_failed"];
const nativeGasHint = (cfg: Config, gasToken: string) => gasToken === "native" ? "" : ` To pay gas in ${cfg.identity.nativeSymbol} instead, review again with --native-gas.`;

/** Every policy exception records its reasons. Without any, a retry re-evaluates the request, so there is nothing to approve. */
export function assertNeedsApproval(r: OperationRecord) {
  if (r.status === "approval_required" && !r.reasons?.length) throw new WalletError("validation_failed", "This request does not need terminal approval; retry it with the same request ID");
}

function result(r: OperationRecord) {
  const nativeGas = r.intent.gasToken === "native" && (r.status === "confirmed" || r.status === "reverted") && r.consumed?.native !== undefined
    ? (BigInt(r.consumed.native) - (r.status === "confirmed" && r.intent.token === "native" ? BigInt(r.intent.amount) : 0n)).toString() : undefined;
  const { registryApproval, ...publicIntent } = r.intent;
  const intent = registryApproval ? { ...publicIntent, registryApproval: { ...registryApproval, parent_signature: "[redacted]" } } : publicIntent;
  const eventMissing = r.status === "confirmed" && r.lastError === "registry_event_missing";
  const registryError = eventMissing || (r.status === "reverted" && isRegistryIntent(r.intent) && r.lastError?.startsWith("registry_")) ? r.lastError : undefined;
  const interrupted = r.status === "approval_required" && TEMPORARY_ERRORS.includes(r.lastError ?? "");
  return { request_id: r.requestId, intent, registry_error: registryError, ...(eventMissing ? { next_action: "The operation succeeded on-chain but its registry event was not found. Check get_agent_registry_status before relying on this change." } : registryError ? { next_action: "Refresh registry status. Invalid or expired parent consent requires a fresh approval in Portal and a new request UUID." } : interrupted ? { next_action: `A temporary RPC failure interrupted this request. Retry with the same request ID${r.reasons?.length ? "." : "; terminal approval is not needed."}` } : {}), status: r.status, user_op_hash: r.userOpHash, replacement_user_op_hash: r.replacement?.userOpHash, transaction_hash: r.transactionHash, actual_native_gas_cost_wei: nativeGas, reasons: r.status === "approval_required" ? r.reasons : undefined, attempts: r.attempts, last_error: ["confirmed", "reverted", "superseded"].includes(r.status) ? undefined : r.lastError };
}
