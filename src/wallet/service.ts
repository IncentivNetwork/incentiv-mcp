import { assertRegistryApproved, isRegistryIntent, registryCapability, linkBlocker } from "../agent-registry.js";
import { randomBytes } from "node:crypto";
import { formatUnits, getAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { type Hex } from "viem";
import { z } from "zod";
import { type Config } from "../config.js";
import { Ctx } from "../context.js";
import { NetworkError } from "../network.js";
import { userOpToJson } from "../userop.js";
import { publicWallet, unlockWallet, WalletError } from "./keystore.js";
import { localWalletStore, type WalletSession, type WalletStore } from "./store.js";
import { Journal, digest, holdsMainNonce, intentSchema, ownsNonce, terminal, type Intent, type OperationRecord } from "./journal.js";
import { addSpend, authorize, limitsSchema, newAdministration, policyViolations, registryParentAllowed, x402Violations, type Limits, type Spend } from "./policy.js";
import { MIN_SWAP_REMAINING_SECONDS, SWAP_DEADLINE_SECONDS, WalletChain, isTransportFailure } from "./chain.js";
import { validateOperation } from "./validate.js";
import { httpsTransport, type HttpTransport } from "../x402/http.js";
import { incentivX402, parsePaymentRequired, paymentHeader, paymentNonceKey, selectRequirements, settlement, x402Config, X402_SCHEME, type PaymentRequirements } from "../x402/protocol.js";
import { MAX_RESPONSE_BYTES, responseContent, usdcAmount, USDC_DECIMALS, x402Request, type X402Request } from "../x402/request.js";

// Source-controlled local candidate signing, explicitly authorized for acceptance testing.
// Every request still needs the authenticated wallet policy and all transaction checks.
// This is NOT publication approval: publication is a separate, manual decision.
// There is no environment-variable or MCP-argument override.
export const WALLET_CANDIDATE_SIGNING_ENABLED = true;

const APPROVAL_FLOW = "Open Portal, review and sign the connection (it is permanent: Portal and this wallet offer no way to disconnect it), then pass its approval JSON to link_agent with a new request UUID. Never sign a supplied digest.";
/** Local conditions that sign_agent_link reports as link_blocked. Any other error, such as a damaged journal, stays an error. */
const LINK_CONSENT_REFUSALS = ["policy_not_configured", "wallet_locked", "policy_expired", "registry_parent_not_allowed", "wallet_release_unreviewed", "capability_manifest_unapproved", "operation_pending"];
const linkRefusal = (status: object, [code, message]: [string, string]) => ({ ...status, link_blocked: code, next_action: `${message}. Do not ask the user to sign in Portal.` });

export class WalletService {
  constructor(readonly ctx: Ctx, readonly store: WalletStore = localWalletStore(ctx.config), readonly chain: WalletChain = new WalletChain(ctx), private readonly signingEnabled = WALLET_CANDIDATE_SIGNING_ENABLED, readonly http: HttpTransport = httpsTransport) {}
  /** Loads `@incentiv/x402` on first payment; tests replace it. */
  x402Loader: typeof incentivX402 = incentivX402;
  create() { return this.store.createOrLoad(); }
  private async enabled(s: WalletSession): Promise<Limits> {
    if (!s.envelope.policy.configured) throw new WalletError("policy_not_configured", "Run incentiv-mcp setup in your local terminal");
    if (!s.envelope.policy.enabled || await s.disabled()) throw new WalletError("wallet_locked", "Wallet is disabled; local administration authorization is required");
    return s.envelope.policy.limits;
  }
  /** The owner's EIP-191 signature over `hash` as raw bytes, which is what the account checks. */
  private async signRaw(s: WalletSession, hash: Hex): Promise<Hex> {
    const privateKey = unlockWallet(this.ctx.config, s.envelope, s.wrappingKey);
    try {
      // viem requires a hex string; V8 cannot guarantee zeroization of that temporary.
      return await privateKeyToAccount(`0x${privateKey.toString("hex")}`).signMessage({ message: { raw: hash } });
    } finally { privateKey.fill(0); }
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
    if (isRegistryIntent(r.intent)) await this.chain.verifyRegistry(s.envelope, r.intent, state).catch((error: unknown) => {
      // These signed bytes can never succeed, yet they still hold the nonce, so a fresh request would be refused until they are replaced.
      // Other refusals, such as an unverifiable read or a full parent, can clear, so the request stays retryable as it is.
      if (!(error instanceof WalletError) || !UNSENDABLE_REGISTRY_ERRORS.includes(error.code)) throw error;
      throw new WalletError(error.code, `${error.detail}. Signed request ${r.requestId} cannot be sent but still holds the account nonce, so first clear it with wallet operation resolve ${r.requestId} --replace in your local terminal${r.intent.kind === "link_agent" ? ", then use a fresh Portal approval with a new request ID" : ""}`);
    });
    if (r.intent.kind === "swap") await this.chain.verifySwap(s.envelope, r.intent, limits, state);
    await this.chain.simulate(validated);
    await this.canSubmit(s, r);
    if (r.deadline && r.deadline <= Math.floor(Date.now() / 1000) + MIN_SWAP_REMAINING_SECONDS) throw new WalletError("operation_pending", "Operation deadline is too close; reconcile or review a same-nonce replacement");
  }
  private async reconcile(journal: Journal): Promise<void> {
    // Connections are permanent: an unlink an earlier build left awaiting approval can never be approved, so it is cancelled.
    for (const r of journal.data.records) if (r.intent.kind === "unlink_agent" && (r.status === "preparing" || r.status === "approval_required")) {
      delete r.approval; r.lastError = "registry_unlink_unsupported"; await journal.transition(r, "cancelled");
    }
    for (const r of journal.data.records.filter(r => ownsNonce(r.status))) {
      if (r.status === "signed") {
        // No network submission was started; exact bytes remain retryable. An x402 payment that was never sent
        // is known only to this computer, so once its deadline passes the seller can no longer accept it.
        if (r.intent.kind === "x402_payment" && r.deadline! <= Math.floor(Date.now() / 1000)) { r.lastError = "x402_payment_expired"; await journal.transition(r, "expired"); }
        continue;
      }
      if (r.status === "submitting") await journal.transition(r, "submission_unknown");
      try {
        const searched = r.searchedBlock;
        const receipt = await this.chain.receipt(r);
        // Search progress is kept, so a payment settled long ago is reached over several reconciliations.
        if (!receipt && r.searchedBlock !== searched) { r.sequence = ++journal.data.sequence; await journal.save(); }
        if (!receipt && r.replacement?.signed) {
          // The replacement's own search starts from the signing block: the payment's progress says nothing about it.
          const replaced = await this.chain.receipt({ ...r, operation: r.replacement.operation, userOpHash: r.replacement.userOpHash, searchedBlock: undefined });
          if (replaced) {
            const gasToken = r.replacement!.gasToken ?? "native";
            r.consumed = gasToken === "native" ? { native: replaced.actualGasCost.toString() } : { [gasToken]: r.replacement!.gasCharge! }; r.consumedAt = Date.now(); r.transactionHash = replaced.transactionHash;
            // A mined replacement consumes the nonce even if its execution reverted.
            await journal.transition(r, "superseded"); continue;
          }
        }
        // For an x402 payment, submitted means the seller reported its settlement; keep that until the receipt shows.
        const settledBySeller = r.intent.kind === "x402_payment" && r.status === "submitted";
        if (!receipt) { if (r.status === "submitted" && !settledBySeller) await journal.transition(r, "submission_unknown"); continue; }
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
        if (r.status === "submitted" && r.intent.kind !== "x402_payment") await journal.transition(r, "submission_unknown");
      }
    }
  }
  /**
   * Connections are permanent: an unlink an earlier build signed is never sent, whatever the current policy says.
   * Checked before policy, so the refusal names the only way to free the nonce it holds.
   */
  private refuseUnlink(r: OperationRecord): void {
    if (r.intent.kind === "unlink_agent") throw new WalletError("registry_unlink_unsupported", `Agent connections are permanent; this wallet does not unlink agents. Signed request ${r.requestId} cannot be sent but still holds the account nonce, so first clear it with wallet operation resolve ${r.requestId} --replace in your local terminal`);
  }
  private async submit(s: WalletSession, journal: Journal, r: OperationRecord): Promise<void> {
    if (r.intent.kind === "x402_payment") throw new WalletError("validation_failed", "This wallet never relays an x402 payment itself");
    await this.canSubmit(s, r);
    if (!r.operation || !r.userOpHash) throw new WalletError("wallet_recovery_required", "Signed operation is missing");
    if (r.deadline && r.deadline <= Math.floor(Date.now() / 1000)) throw new WalletError("operation_pending", "Signed operation deadline expired; review a same-nonce replacement with wallet operation resolve --replace");
    this.refuseUnlink(r);
    // A registry request signed under pins this release no longer approves, or before a release without the registry,
    // cannot be sent; approving new pins waits for its nonce, so only a same-nonce replacement clears it.
    if (isRegistryIntent(r.intent)) try { assertRegistryApproved(this.ctx.config, s.envelope); } catch (error) {
      if (!(error instanceof WalletError)) throw error;
      if (error.code === "capability_manifest_unapproved") throw new WalletError(error.code, `Registry request ${r.requestId} was signed before this release changed the Agent Registry pins, so it cannot be sent. Clear it with wallet operation resolve ${r.requestId} --replace in your local terminal, then run wallet capabilities approve`);
      if (error.code === "registry_unavailable") throw new WalletError(error.code, `Registry request ${r.requestId} was signed, but this release does not include the Agent Registry, so it cannot be sent. Clear it with wallet operation resolve ${r.requestId} --replace in your local terminal`);
      throw error;
    }
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
      if (journal.data.records.some(holdsMainNonce)) throw new WalletError("operation_pending", "An unresolved operation owns the account nonce; reconcile it first");
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
        r.operation!.signature = await this.signRaw(s, validated.hash);
        await this.canSubmit(s, r);
        await journal.transition(r, "signed"); // fsync completes before any submission.
      } catch (error) {
        // An RPC outage says nothing about the request, so its ID and any local approval stay usable.
        const failure = error instanceof WalletError ? error : isTransportFailure(error) ? new WalletError("rpc_unavailable", "Could not read chain state from RPC; retry this request") : undefined;
        // Without an approval the operation may have been rebuilt, so earlier reasons may not describe it; a retry evaluates it again.
        if (r.status === "preparing" && TEMPORARY_ERRORS.includes(failure?.code ?? "")) { r.lastError = failure!.code; if (!r.approval) delete r.reasons; await journal.transition(r, "approval_required"); }
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
  private agentLinkUrl(s: WalletSession) {
    const cap = registryCapability(this.ctx.config), url = new URL(this.ctx.config.endpoints.portalUrl!);
    url.searchParams.set("agent", s.envelope.account);
    url.searchParams.set("chain_id", String(this.ctx.config.identity.chainId));
    url.searchParams.set("registry", cap.proxy.address);
    return url;
  }
  /** The Portal URL that asks the user to approve this agent's connection for link_agent. Reads only. */
  async prepareAgentLink() {
    return this.store.session(async s => {
      const url = this.agentLinkUrl(s), status = await this.chain.registryStatus(s.envelope);
      const blocked = linkBlocker(status, status.deployed);
      return blocked ? linkRefusal(status, blocked) : { ...status, portal_url: url.href, next_action: APPROVAL_FLOW };
    });
  }
  /**
   * The local conditions for signing link consent to `parent`, each refused with a WalletError: an enabled
   * policy that allows the parent, a release that may sign, an approved registry capability, and no
   * registry request that may still land. Requests that only await approval are returned as `queued`.
   */
  private async linkConsentChecks(s: WalletSession, parent: string) {
    const limits = await this.enabled(s);
    // The 15-minute margin is checked against the block's clock with the deadline; an expired policy needs no chain read.
    if (limits.expiresAt && limits.expiresAt <= Date.now()) throw new WalletError("policy_expired", "Local wallet policy has expired. Renew it with incentiv-mcp setup in your local terminal");
    if (!registryParentAllowed(limits, parent)) throw new WalletError("registry_parent_not_allowed", "Local wallet policy does not allow this parent. Add it with incentiv-mcp setup in your local terminal, then call sign_agent_link again");
    if (!this.signingEnabled) throw new WalletError("wallet_release_unreviewed", "This release has candidate signing disabled, so it cannot sign link consent. Use prepare_agent_link and the Portal approval flow");
    assertRegistryApproved(this.ctx.config, s.envelope);
    const registry = (await Journal.open(s)).data.records.filter(r => isRegistryIntent(r.intent) && !terminal(r.status));
    // A link or unlink that may still land would change this agent's registry nonce, voiding any consent signed now.
    const pending = registry.find(r => ownsNonce(r.status));
    // A signed request, or one the network may have dropped, settles only when it is sent again or replaced.
    const resendable = pending?.status === "signed" || pending?.status === "submission_unknown";
    if (resendable && pending.deadline && pending.deadline <= Math.floor(Date.now() / 1000)) throw new WalletError("operation_pending", `Registry request ${pending.requestId} was ${pending.status === "signed" ? "signed but never submitted" : "never confirmed"}, and its deadline has passed. Resolve it with wallet operation resolve ${pending.requestId} --replace in your local terminal, then call sign_agent_link again`);
    // An unlink recorded by an earlier build is never sent again, so only a same-nonce replacement clears it.
    if (pending?.intent.kind === "unlink_agent" && pending.status === "signed") throw new WalletError("operation_pending", `Registry request ${pending.requestId} is an unlink signed by an earlier build, which this wallet no longer sends. Clear it with wallet operation resolve ${pending.requestId} --replace in your local terminal, then call sign_agent_link again`);
    if (pending?.intent.kind === "unlink_agent" && pending.status === "submission_unknown") throw new WalletError("operation_pending", `Registry request ${pending.requestId} is an unlink from an earlier build that was submitted but never confirmed. Check it with get_agent_operation; if it does not confirm, clear it with wallet operation resolve ${pending.requestId} --replace in your local terminal, then call sign_agent_link again`);
    if (pending?.status === "signed") throw new WalletError("operation_pending", `Registry request ${pending.requestId} is signed but was never submitted. Retry link_agent with that request_id to submit it, then call sign_agent_link again`);
    if (pending?.status === "submission_unknown") throw new WalletError("operation_pending", `Registry request ${pending.requestId} was submitted but has not been confirmed and may have been dropped. Retry link_agent with that request_id to send it again, check it with get_agent_operation, then call sign_agent_link again`);
    if (pending) throw new WalletError("operation_pending", `Registry request ${pending.requestId} is still unresolved. Check it with get_agent_operation until it settles, then call sign_agent_link again`);
    // An unlink from an earlier build that awaits approval can never be approved now, so it cannot land.
    return { limits, queued: registry.filter(r => r.intent.kind !== "unlink_agent").map(r => r.requestId) };
  }
  /**
   * This agent's own AgentLink consent to `parent`, in a Portal URL, so Portal can submit the link from the
   * parent's account once the user trusts this agent. That needs the same authenticated local policy as
   * link_agent: the parent must be allowed, and the wallet enabled for signing. The signature names this one
   * parent, which still has to send the link itself, so it gives nobody else a way to link this agent. It
   * expires no later than the local policy, and nothing here can withdraw it before then.
   */
  async signAgentLink(parent: string) {
    return this.store.session(async s => {
      const url = this.agentLinkUrl(s), requested = getAddress(parent);
      // Local checks decide before any registry read, and their refusals take the same shape as the registry's.
      let local: Awaited<ReturnType<WalletService["linkConsentChecks"]>>;
      try { local = await this.linkConsentChecks(s, requested); } catch (error) {
        if (error instanceof WalletError && LINK_CONSENT_REFUSALS.includes(error.code)) return linkRefusal({ agent: s.envelope.account, requested_parent: requested }, [error.code, error.detail]);
        throw error;
      }
      const { limits, queued } = local;
      // How soon the policy ends is decided against the block's clock, with the deadline, in agentLinkConsent.
      const { status, blocked, consent } = await this.chain.agentLinkConsent(s.envelope, requested, limits.expiresAt ? Math.floor(limits.expiresAt / 1000) : undefined);
      if (blocked) return linkRefusal(status, blocked);
      // The registry checks a signature through the agent account's ERC-1271, so an undeployed agent cannot consent this way.
      if (!consent) return { ...status, link_blocked: "registry_agent_not_deployed", next_action: "This agent is not deployed yet, so it cannot sign link consent. Call prepare_agent_link and use the Portal approval flow with link_agent instead." };
      await this.canSubmit(s);
      const signature = await this.signRaw(s, consent.digest);
      await this.chain.verifyAgentLinkSignature(s.envelope, consent.digest, signature, consent.block);
      // As for operations, the wallet must still be enabled and owned once the signature exists.
      await this.canSubmit(s);
      url.searchParams.set("parent", requested);
      url.searchParams.set("agent_nonce", consent.nonce.toString());
      url.searchParams.set("agent_deadline", consent.deadline.toString());
      url.searchParams.set("agent_signature", signature);
      return { ...status, portal_url: url.href, agent_signed: true, agent_link: { parent: requested, agent_nonce: consent.nonce.toString(), agent_deadline: consent.deadline.toString() },
        ...(queued.length ? { warning: `Registry request ${queued.join(", ")} has not been sent yet. If it is later approved or retried and lands, it changes this agent's registry nonce and this consent stops working.` } : {}),
        next_action: "Give this URL to the user and tell them the connection is permanent: once made, neither Portal nor this wallet offers a way to disconnect it. In Portal they trust this agent, then submit the connection from their account and pay its fee. Do not call link_agent. Check get_agent_registry_status afterwards. The request expires at agent_deadline, which is never later than local policy expiry, or earlier if this agent's registry nonce changes. Changing local policy does not withdraw it." };
    });
  }
  /** Asks an x402 resource what it costs, without paying. Signs and records nothing. */
  async x402Requirements(args: Record<string, unknown>) {
    const req = x402Request(args);
    const response = await this.http({ ...req, maxBytes: MAX_RESPONSE_BYTES, timeoutMs: 30_000 });
    if (response.status !== 402) return { url: req.url, payment_required: false, content: responseContent(response), next_action: "This request needs no payment; its answer is in content." };
    const required = parsePaymentRequired(response);
    let accepted: PaymentRequirements | undefined, unsupported: string | undefined;
    try { accepted = selectRequirements(required, this.ctx.config); }
    catch (error) { if (!(error instanceof WalletError)) throw error; unsupported = error.detail; }
    // Whether local policy would allow it, read without unlocking the key. Balance and gas are checked when paying.
    const reasons = accepted ? await this.store.session(async s => s.envelope.policy.configured ? x402Violations(s.envelope.policy.limits, req.origin, accepted.payTo, accepted.amount) : ["policy_not_configured"]).catch(() => ["wallet_unavailable"]) : undefined;
    return {
      url: req.url, payment_required: true, payable: !!accepted, ...(unsupported ? { unsupported } : {}),
      ...(accepted ? { price: { amount: formatUnits(BigInt(accepted.amount), USDC_DECIMALS), amount_atomic: accepted.amount, asset: "USDC", pay_to: getAddress(accepted.payTo), scheme: accepted.scheme, network: accepted.network, max_timeout_seconds: accepted.maxTimeoutSeconds, settles_before_handler: accepted.extra?.paymentFlow === "upfront" } } : {}),
      gas: "Paid on top of the price: about 0.03 USDC through the paymaster (minimum 0.026), or CENT with gas_token native.",
      description: typeof required.resource?.description === "string" ? required.resource.description.slice(0, 1024) : undefined,
      ...(reasons ? { policy: { allowed: reasons.length === 0, reasons } } : {}),
      next_action: !accepted ? "This wallet cannot pay this resource." : reasons?.length ? "Local wallet policy would refuse this payment; the user can change it with incentiv-mcp setup." : "To pay, call pay_x402_resource with the same request and max_amount set to at most the price you accept.",
    };
  }

  /**
   * Pays an x402 resource from the smart account and returns its answer. The payment is an `incentiv-userop`
   * user operation on its own nonce lane, which only the seller's facilitator submits; this wallet signs it only
   * after the same validation, simulation and policy checks as a transfer, and journals it before it leaves.
   */
  async payX402(args: Record<string, unknown>) {
    const requestId = z.string().uuid().parse(args.request_id).toLowerCase();
    const req = x402Request(args);
    const maxAmount = usdcAmount(args.max_amount);
    const cfg = this.ctx.config, xcfg = x402Config(cfg);
    const gasRef = String(args.gas_token ?? "USDC");
    const gasToken = ["native", cfg.identity.nativeSymbol.toLowerCase()].includes(gasRef.toLowerCase()) ? "native" : gasRef.toUpperCase() === "USDC" || gasRef.toLowerCase() === xcfg.usdc.toLowerCase() ? xcfg.usdc.toLowerCase() : undefined;
    if (!gasToken) throw new WalletError("validation_failed", "gas_token must be USDC or native for an x402 payment");
    const request = digest({ ...req, maxAmount: maxAmount.toString(), gasToken });
    return this.store.session(async s => {
      const limits = await this.enabled(s);
      const journal = await Journal.open(s); await this.reconcile(journal);
      const existing = journal.data.records.find(r => r.requestId === requestId);
      if (existing) {
        if (existing.intent.kind !== "x402_payment" || existing.intent.x402!.request !== request) throw new WalletError("idempotency_conflict", "This request ID is permanently bound to a different request");
        // A payment that never left this computer is sent only if current wallet policy still allows it (checked in
        // deliverX402); one that did is resent unchanged while the seller can still accept it, since it may hold it.
        if (["signed", "submission_unknown"].includes(existing.status)) return this.deliverX402(s, journal, existing, req, limits);
        // Whether an answer handed back earlier reached the caller is unknown here, so a retry may ask the seller again.
        if (existing.status === "submitted" || existing.status === "confirmed") return this.redeliverX402(journal, existing, req);
        // Either the payment or its cancellation will take the nonce lane; a new request ID uses another lane, so both could pay.
        if (existing.status === "superseding") return { ...x402Result(existing), next_action: "A cancellation of this payment is pending, and the payment itself may still settle instead. Check get_agent_operation and wait until it shows superseded (cancelled, nothing paid) or confirmed (paid; retry this request ID for the answer). Buying again with a new request ID before then may pay twice." };
        return { ...x402Result(existing), next_action: "Use a new request ID to try again." };
      }
      if (!limits.x402) throw new WalletError("policy_denied", "x402 payments are off in local wallet policy; the user can enable them with incentiv-mcp setup");
      const early = x402Violations(limits, req.origin, "0x0000000000000000000000000000000000000000", "0").filter(r => r !== "x402_pay_to_not_allowed");
      if (early.length) throw new WalletError("policy_denied", `Local wallet policy refuses this resource: ${early.join(", ")}`);

      const unpaid = await this.http({ ...req, maxBytes: MAX_RESPONSE_BYTES }).catch((error: unknown) => {
        if (error instanceof WalletError) throw error;
        throw new WalletError("x402_request_failed", `The resource could not be reached, so nothing was paid: ${error instanceof Error ? error.message.slice(0, 200) : "unknown error"}`);
      });
      if (unpaid.status !== 402) return { request_id: requestId, status: "not_required", content: responseContent(unpaid), next_action: "No payment was needed or made." };
      const required = parsePaymentRequired(unpaid);
      const accepted = selectRequirements(required, cfg);
      const amount = BigInt(accepted.amount);
      if (amount > maxAmount) throw new WalletError("x402_price_above_max", `The resource asks ${formatUnits(amount, USDC_DECIMALS)} USDC, above max_amount ${formatUnits(maxAmount, USDC_DECIMALS)}; nothing was paid`);
      const payTo = getAddress(accepted.payTo).toLowerCase();
      const refused = x402Violations(limits, req.origin, payTo, accepted.amount);
      if (refused.length) throw new WalletError("policy_denied", `Local wallet policy refuses this payment: ${refused.join(", ")}; nothing was paid`);

      const paymentId = `0x${randomBytes(32).toString("hex")}` as Hex;
      const validUntil = Math.floor(Date.now() / 1000) + accepted.maxTimeoutSeconds;
      const intent = intentSchema.parse({
        intentSchemaVersion: 1, kind: "x402_payment", token: xcfg.usdc.toLowerCase(), amount: accepted.amount, gasToken, to: payTo, slippageBps: 0, feeTier: 3000,
        x402: { url: req.url, origin: req.origin, method: req.method, request, maxAmount: maxAmount.toString(), accepted: JSON.stringify(accepted), ...(required.resource ? { resource: JSON.stringify(required.resource) } : {}), paymentId, validUntil },
      });
      const r = await journal.create(requestId, intent);
      try {
        const state = await this.chain.state(s.envelope);
        const key = paymentNonceKey(paymentId, validUntil);
        const [balances, laneNonce, x402] = await Promise.all([this.chain.balances(s.envelope, this.balanceTokens(limits)), this.chain.laneNonce(s.envelope, key, state.block), this.x402Loader()]);
        // The reference client builds the operation; it then has to pass @incentiv/x402's own check and this wallet's.
        const prepared = await x402.preparePayment(x402.makeChain(xcfg), { account: s.envelope.account as `0x${string}`, owner: s.envelope.owner as `0x${string}`, salt: 0n, asset: xcfg.usdc, payTo: payTo as `0x${string}`, amount, paymentId, validUntil, gas: gasToken === "native" ? "native" : "token" })
          .catch((error: unknown) => { throw new WalletError("validation_failed", `Could not prepare the payment: ${error instanceof Error ? error.message.slice(0, 300) : "unknown error"}`); });
        try { x402.checkPaysRequirements(x402.decodePaymentOp(prepared.op, xcfg), accepted); }
        catch { throw new WalletError("validation_failed", "The prepared payment does not pay exactly what the resource asked"); }
        const wire = userOpToJson(prepared.op);
        const validated = validateOperation(cfg, s.envelope, intent, wire, { nonce: laneNonce, deployed: state.deployed, hash: prepared.userOpHash });
        const used = journal.used();
        const violations = policyViolations(limits, { token: intent.token, amount: intent.amount, swap: false, slippage: 0, spend: validated.spend, used, balances, gasCost: validated.gasCost, fee: validated.op.maxFeePerGas, gasUnits: validated.gasUnits, gasToken, gasCharge: validated.gasCharge, calls: validated.calls, x402: { origin: req.origin, payTo } });
        if (violations.length) { r.reasons = violations; throw new WalletError("policy_denied", `Local wallet policy refuses this payment: ${violations.join(", ")}; nothing was paid`); }
        for (const [token, value] of Object.entries(validated.spend)) if (BigInt(balances[token] ?? "0") < BigInt(value)) throw new WalletError("policy_denied", "Balance cannot cover the price plus the maximum gas payment; nothing was paid");
        r.operation = wire; r.userOpHash = validated.hash; r.nonce = laneNonce.toString(); r.deadline = validUntil; r.reservation = validated.spend; r.fromBlock = state.block.toString();
        await this.chain.simulate(validated);
        if (validUntil <= Math.floor(Date.now() / 1000) + 5) throw new WalletError("validation_failed", "The seller's payment window closed while the payment was prepared; retry with a new request ID");
        assertPolicyLive(limits, "it expired while the payment was prepared; nothing was paid");
        await this.canSubmit(s, r);
        r.operation.signature = await this.signRaw(s, validated.hash);
        await this.canSubmit(s, r);
        await journal.transition(r, "signed"); // fsync completes before the payment leaves this computer.
      } catch (error) {
        const failure = error instanceof WalletError ? error : isTransportFailure(error) ? new WalletError("rpc_unavailable", "Could not read chain state from RPC; retry with a new request ID") : undefined;
        if (r.status === "preparing") { r.lastError = failure?.code ?? "validation_failed"; await journal.transition(r, "failed"); }
        if (failure) throw failure;
        throw new WalletError("validation_failed", "Local x402 payment preparation failed");
      }
      return this.deliverX402(s, journal, r, req, limits);
    });
  }

  /**
   * A signed payment that has not left this computer is a fresh spend: before it is first sent, it must still
   * pass current wallet policy, balance and its nonce lane, as it did when signed. Its own reservation is
   * excluded from what is already used. A refusal leaves it unsent, and it expires at its deadline.
   */
  private async recheckX402(s: WalletSession, journal: Journal, r: OperationRecord, limits: Limits): Promise<void> {
    const state = await this.chain.stateFor(s.envelope, r);
    if (state.nonce !== BigInt(r.nonce!)) throw new WalletError("operation_pending", "This payment's nonce lane has moved; check get_agent_operation");
    const validated = validateOperation(this.ctx.config, s.envelope, r.intent, { ...r.operation!, signature: "0x" }, { nonce: state.nonce, deployed: state.deployed, hash: r.userOpHash! });
    if (digest(validated.spend) !== digest(r.reservation)) throw new WalletError("wallet_recovery_required", "Operation reservation does not match the signed spend");
    const balances = await this.chain.balances(s.envelope, this.balanceTokens(limits)), used = journal.used();
    for (const [token, amount] of Object.entries(r.reservation)) addSpend(used, token, -BigInt(amount));
    const violations = policyViolations(limits, { token: r.intent.token, amount: r.intent.amount, swap: false, slippage: 0, spend: validated.spend, used, balances, gasCost: validated.gasCost, fee: validated.op.maxFeePerGas, gasUnits: validated.gasUnits, gasToken: r.intent.gasToken, gasCharge: validated.gasCharge, calls: validated.calls, x402: { origin: r.intent.x402!.origin, payTo: r.intent.to! } });
    if (violations.length) throw new WalletError("policy_denied", `Local wallet policy no longer allows this payment: ${violations.join(", ")}; it was never sent and expires unpaid`);
    for (const [token, amount] of Object.entries(validated.spend)) if (BigInt(balances[token] ?? "0") < BigInt(amount)) throw new WalletError("policy_denied", "Balance no longer covers this payment; it was never sent and expires unpaid");
  }

  /**
   * The seller reported or the chain shows this payment settled, but its answer may not have reached the caller:
   * the process can stop after the answer is recorded and before the tool returns. For a GET, the same signed
   * payment is offered to the seller once more; it owns one nonce, so it cannot be charged again, and the seller
   * may serve it. A POST is never repeated automatically: a seller that accepts the payment again would run its
   * handler a second time.
   */
  private async redeliverX402(journal: Journal, r: OperationRecord, req: X402Request) {
    const x = r.intent.x402!;
    let response: Awaited<ReturnType<typeof this.http>> | undefined;
    if (req.method === "GET") {
      const header = paymentHeader(JSON.parse(x.accepted), x.resource ? JSON.parse(x.resource) : undefined, r.operation!, r.userOpHash as Hex, x.paymentId as Hex, x.validUntil);
      response = await this.http({ ...req, headers: { ...req.headers, "payment-signature": header }, maxBytes: MAX_RESPONSE_BYTES }).catch(() => undefined);
      if (response && response.status >= 200 && response.status < 300) {
        r.delivered = true; r.sequence = ++journal.data.sequence; await journal.save();
        return { ...x402Result(r), content_delivered: true, content: responseContent(response), next_action: "This payment had settled without its answer; the seller has now served it. Nothing more was paid." };
      }
    }
    const where = r.transactionHash ? ` in ${r.transactionHash}` : "";
    const answer = r.delivered ? "its answer was handed back when it was paid, but this wallet cannot tell whether it reached you" : "its answer was lost";
    const again = req.method === "GET" ? "the seller did not serve it again" : "this wallet does not resend a paid POST, because the seller could run it a second time";
    return { ...x402Result(r), content_delivered: false, ...(response ? { http_status: response.status } : {}), next_action: `This payment settled${where} and ${answer}; ${again}. Nothing more was paid. Buying again with a new request ID pays again; if the answer was lost, ask the seller to honour this payment instead.` };
  }

  /** The seller's deadline passed: an unsent payment expires; one the seller may hold stays reserved until resolved. */
  private async pastDeadlineX402(journal: Journal, r: OperationRecord) {
    if (r.status === "signed") { r.lastError = "x402_payment_expired"; await journal.transition(r, "expired"); return { ...x402Result(r), next_action: "The payment expired before it was sent, so nothing was paid. Use a new request ID." }; }
    return { ...x402Result(r), next_action: X402_UNKNOWN_ACTION(r.requestId) };
  }
  /** Sends the signed payment with the request, and records what the seller answered. */
  private async deliverX402(s: WalletSession, journal: Journal, r: OperationRecord, req: X402Request, limits: Limits) {
    const x = r.intent.x402!;
    if (x.validUntil <= Math.floor(Date.now() / 1000)) return this.pastDeadlineX402(journal, r);
    // First delivery is a fresh spend on either path: policy may have expired or changed while the payment was
    // simulated or waited unsent. A payment the seller may already hold is resent unchanged.
    const before = r.status, first = before === "signed";
    if (first) await this.recheckX402(s, journal, r, limits);
    await this.canSubmit(s, r);
    if (first) assertPolicyLive(limits, "it was never sent and expires unpaid");
    r.attempts++;
    await journal.transition(r, "submitting"); // From here the seller may hold the signed payment.
    // While that write completes, the wallet can be disabled, policy can expire or the deadline can pass. They are
    // checked again at the request itself, with nothing awaited in between; a refusal records that it never left.
    const unsent = async () => { r.attempts--; await journal.transition(r, before); };
    try { await this.canSubmit(s, r); if (first) assertPolicyLive(limits, "it was never sent and expires unpaid"); }
    catch (error) { await unsent(); throw error; }
    if (x.validUntil <= Math.floor(Date.now() / 1000)) { await unsent(); return this.pastDeadlineX402(journal, r); }
    const header = paymentHeader(JSON.parse(x.accepted), x.resource ? JSON.parse(x.resource) : undefined, r.operation!, r.userOpHash as Hex, x.paymentId as Hex, x.validUntil);
    let response;
    try { response = await this.http({ ...req, headers: { ...req.headers, "payment-signature": header }, maxBytes: MAX_RESPONSE_BYTES }); }
    catch {
      r.lastError = "submission_unknown"; await journal.transition(r, "submission_unknown");
      return { ...x402Result(r), next_action: `The seller did not answer, so the payment may or may not settle. Retry pay_x402_resource with the same request ID while the deadline is open; ${X402_UNKNOWN_ACTION(r.requestId)}` };
    }
    const settled = settlement(response);
    const paid = response.status >= 200 && response.status < 300 && settled?.success === true;
    if (paid) {
      if (typeof settled.transaction === "string" && /^0x[0-9a-fA-F]{64}$/.test(settled.transaction)) r.transactionHash = settled.transaction.toLowerCase();
      delete r.lastError; r.delivered = true; await journal.transition(r, "submitted");
    } else {
      r.lastError = response.status === 402 ? "x402_payment_refused" : "x402_settlement_unconfirmed";
      await journal.transition(r, "submission_unknown");
    }
    let sellerError: string | undefined;
    if (response.status === 402) try { sellerError = String(parsePaymentRequired(response).error ?? "").slice(0, 300) || undefined; } catch { /* no readable reason */ }
    return {
      ...x402Result(r), settlement: settled ? { success: settled.success, transaction: settled.transaction, network: settled.network, payer: settled.payer, error_reason: settled.errorReason } : undefined,
      ...(sellerError ? { seller_error: sellerError } : {}),
      // A refused or unconfirmed payment's content is not returned: the seller has not been paid for it.
      ...(paid ? { content: responseContent(response) } : { http_status: response.status }),
      next_action: paid ? "Paid. The settlement is confirmed on chain by get_agent_operation." : response.status === 402 ? `The seller refused the payment. ${X402_UNKNOWN_ACTION(r.requestId)}` : `The seller answered without confirming settlement. ${X402_UNKNOWN_ACTION(r.requestId)}`,
    };
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
      // Only the seller submits an x402 payment; this wallet never relays it, and cancels it only by replacement.
      else if (r.intent.kind !== "x402_payment" && (r.status === "signed" || r.status === "submission_unknown")) await this.submit(s, journal, r);
      return result(r);
    });
  }

  async reviewReplacement(id: string, nativeGas = false) {
    return this.store.session(async s => {
      await this.enabled(s);
      const journal = await Journal.open(s); await this.reconcile(journal);
      const r = journal.data.records.find(r => r.requestId === id);
      if (!r || !ownsNonce(r.status) || r.replacement?.signed) throw new WalletError("operation_pending", "Replacement requires an unresolved original operation without a signed replacement");
      // For an x402 payment this cancels it: any operation on its nonce lane makes the payment unusable (SPEC 6).
      const state = await this.chain.stateFor(s.envelope, r);
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
      const state = await this.chain.stateFor(s.envelope, r);
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
      replacement.operation.signature = await this.signRaw(s, validated.hash);
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
/** Registry refusals that the same signed bytes can never get past. */
const UNSENDABLE_REGISTRY_ERRORS = ["registry_approval_stale", "registry_approval_expired", "registry_approval_invalid", "registry_link_changed", "registry_unlink_unsupported"];
const PORTAL_APPROVAL_ERRORS = ["registry_approval_stale", "registry_approval_expired", "registry_approval_invalid"];
/** What an agent should do after the registry reverted its request; only a link's parent consent comes from a Portal approval. */
function registryNextAction(kind: Intent["kind"], code: string) {
  // Only an unlink recorded by an earlier build reaches this: connections are permanent, so it is never retried.
  if (kind === "unlink_agent") return code === "registry_link_changed"
    ? "This agent is no longer linked to that parent, so there was nothing to unlink. Check get_agent_registry_status; no Portal approval is needed."
    : `The registry refused this unlink (${code}). Connections are permanent and this wallet no longer sends unlinks; check get_agent_registry_status.`;
  return PORTAL_APPROVAL_ERRORS.includes(code)
    ? "Refresh registry status. Invalid or expired parent consent requires a fresh approval in Portal and a new request UUID."
    : `The registry refused this link (${code}). Check get_agent_registry_status before asking the user for a fresh Portal approval with a new request UUID.`;
}
const GAS_FIXABLE_ERRORS = ["policy_denied", "simulation_failed", "validation_failed"];
const nativeGasHint = (cfg: Config, gasToken: string) => gasToken === "native" ? "" : ` To pay gas in ${cfg.identity.nativeSymbol} instead, review again with --native-gas.`;

/** Every policy exception records its reasons. Without any, a retry re-evaluates the request, so there is nothing to approve. */
export function assertNeedsApproval(r: OperationRecord) {
  if (r.status === "approval_required" && !r.reasons?.length) throw new WalletError("validation_failed", "This request does not need terminal approval; retry it with the same request ID");
}

/** Policy expiry is checked again at the last moment before a payment is signed or first leaves this computer. */
function assertPolicyLive(limits: Limits, consequence: string) {
  if (limits.expiresAt && Date.now() >= limits.expiresAt) throw new WalletError("policy_denied", `Local wallet policy expired; ${consequence}`);
}

const X402_UNKNOWN_ACTION = (id: string) => `Its amount stays reserved until the payment settles or is cancelled. Check get_agent_operation; to cancel it, the user runs incentiv-mcp wallet operation resolve ${id} --replace in their own terminal.`;

/** An x402 record for the agent: the request and payment, without the seller's raw JSON. */
function x402Result(r: OperationRecord) {
  const { accepted, resource, request, ...x402 } = r.intent.x402!;
  return { ...result(r), intent: { kind: r.intent.kind, amount: formatUnits(BigInt(r.intent.amount), USDC_DECIMALS), asset: "USDC", pay_to: r.intent.to, gas_token: r.intent.gasToken, scheme: X402_SCHEME, ...x402 } };
}

function result(r: OperationRecord) {
  const nativeGas = r.intent.gasToken === "native" && (r.status === "confirmed" || r.status === "reverted") && r.consumed?.native !== undefined
    ? (BigInt(r.consumed.native) - (r.status === "confirmed" && r.intent.token === "native" ? BigInt(r.intent.amount) : 0n)).toString() : undefined;
  const { registryApproval, ...publicIntent } = r.intent;
  const intent = registryApproval ? { ...publicIntent, registryApproval: { ...registryApproval, parent_signature: "[redacted]" } } : publicIntent;
  const eventMissing = r.status === "confirmed" && r.lastError === "registry_event_missing";
  const registryError = eventMissing || (r.status === "reverted" && isRegistryIntent(r.intent) && r.lastError?.startsWith("registry_")) ? r.lastError : undefined;
  const interrupted = r.status === "approval_required" && TEMPORARY_ERRORS.includes(r.lastError ?? "");
  return { request_id: r.requestId, intent, registry_error: registryError, ...(eventMissing ? { next_action: "The operation succeeded on-chain but its registry event was not found. Check get_agent_registry_status before relying on this change." } : registryError ? { next_action: registryNextAction(r.intent.kind, registryError) } : interrupted ? { next_action: `A temporary RPC failure interrupted this request. Retry with the same request ID${r.reasons?.length ? "." : "; terminal approval is not needed."}` } : {}), status: r.status, user_op_hash: r.userOpHash, replacement_user_op_hash: r.replacement?.userOpHash, transaction_hash: r.transactionHash, actual_native_gas_cost_wei: nativeGas, reasons: r.status === "approval_required" ? r.reasons : undefined, attempts: r.attempts, last_error: ["confirmed", "reverted", "superseded"].includes(r.status) ? undefined : r.lastError };
}
