import { privateKeyToAccount } from "viem/accounts";
import { type Hex } from "viem";
import { z } from "zod";
import { Ctx } from "../context.js";
import { userOpToJson } from "../userop.js";
import { publicWallet, unlockWallet, WalletError } from "./keystore.js";
import { localWalletStore, type WalletSession, type WalletStore } from "./store.js";
import { Journal, digest, intentSchema, ownsNonce, terminal, type Intent, type OperationRecord } from "./journal.js";
import { addSpend, authorize, limitsSchema, newAdministration, policyViolations, type Limits, type Spend } from "./policy.js";
import { MIN_SWAP_REMAINING_SECONDS, SWAP_DEADLINE_SECONDS, WalletChain } from "./chain.js";
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
    const violations = policyViolations(limits, { token: r.intent.token, tokenOut: r.intent.tokenOut, amount: r.intent.amount, to: r.intent.to, swap: r.intent.kind === "swap", slippage: r.intent.slippageBps, spend: validated.spend, used, balances, gasCost: validated.gasCost, fee: validated.op.maxFeePerGas, gasUnits: validated.gasUnits, gasToken: r.intent.gasToken, gasCharge: validated.gasCharge, calls: validated.calls });
    if (violations.includes("exposure_limit") || (violations.length && (!this.approved(s, r) || r.approval?.liveTest))) throw new WalletError("policy_denied", "Current policy does not permit this signed operation; reservation preserved");
    if (r.approval && !this.approved(s, r)) throw new WalletError("approval_required", "Exact-operation approval expired or policy changed; reservation preserved");
    if (Object.entries(validated.spend).some(([token, amount]) => BigInt(balances[token] ?? "0") < BigInt(amount))) throw new WalletError("policy_denied", "Balance cannot cover input plus maximum gas");
    if (state.fees.baseFeePerGas > validated.op.maxFeePerGas) throw new WalletError("validation_failed", "Gas fee no longer covers the current base fee");
    if (r.intent.kind === "swap") await this.chain.verifySwap(s.envelope, r.intent, limits, state);
    await this.chain.simulate(validated);
    await this.canSubmit(s, r);
    if (r.deadline && r.deadline <= Math.floor(Date.now() / 1000) + MIN_SWAP_REMAINING_SECONDS) throw new WalletError("operation_pending", "Swap deadline is too close; reconcile or review a same-nonce replacement");
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
            r.consumed = { native: replaced.actualGasCost.toString() }; r.consumedAt = Date.now(); r.transactionHash = replaced.transactionHash;
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
        const gas = r.intent.gasToken === "native" ? receipt.actualGasCost : BigInt(r.reservation[r.intent.gasToken] ?? "0") - input;
        if (gas < 0n) throw new WalletError("wallet_recovery_required", "Invalid persisted gas reservation");
        addSpend(spend, r.intent.gasToken, gas);
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
    if (r.deadline && r.deadline <= Math.floor(Date.now() / 1000)) throw new WalletError("operation_pending", "Signed swap deadline expired; review a same-nonce replacement with wallet operation resolve --replace");
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
  async send(kind: "transfer" | "swap", args: Record<string, unknown>, prepareOnly = false) {
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
      if (r?.status === "approval_required") {
        if (r.approval && r.approval.expiresAt <= Date.now()) { await journal.transition(r, "expired"); return result(r); }
        await journal.transition(r, "preparing");
      }
      r ??= await journal.create(requestId, intent);
      try {
        const state = await this.chain.state(s.envelope);
        const balances = await this.chain.balances(s.envelope, this.balanceTokens(limits));
        const used = journal.used();
        // First policy evaluation precedes building; violations may build an unsigned review candidate.
        const initialSpend: Spend = {}; addSpend(initialSpend, intent.token, BigInt(intent.amount));
        const initial = policyViolations(limits, { token: intent.token, tokenOut: intent.tokenOut, amount: intent.amount, to: intent.to, swap: kind === "swap", slippage: intent.slippageBps, spend: initialSpend, used, balances, gasCost: 0n, fee: 0n, gasUnits: 0n, gasToken: intent.gasToken, gasCharge: 0n, calls: [] });
        if (kind === "swap") await this.chain.verifySwap(s.envelope, intent, limits, state);
        if (r.approval && !this.approved(s, r)) delete r.approval;
        if (!r.approval) {
          if (kind === "swap") r.deadline = Math.min(Math.floor(Date.now() / 1000), state.timestamp) + SWAP_DEADLINE_SECONDS;
          const built = await this.chain.build(s.envelope, intent, state, r.deadline);
          r.operation = userOpToJson(built.op); r.userOpHash = built.userOpHash; r.nonce = built.op.nonce.toString();
        }
        const validated = validateOperation(this.ctx.config, s.envelope, intent, r.operation!, { nonce: state.nonce, deployed: state.deployed, hash: r.userOpHash!, deadline: r.deadline });
        const violations = [...new Set([...initial, ...policyViolations(limits, { token: intent.token, tokenOut: intent.tokenOut, amount: intent.amount, to: intent.to, swap: kind === "swap", slippage: intent.slippageBps, spend: validated.spend, used, balances, gasCost: validated.gasCost, fee: validated.op.maxFeePerGas, gasUnits: validated.gasUnits, gasToken: intent.gasToken, gasCharge: validated.gasCharge, calls: validated.calls })])];
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
        if (kind === "swap") await this.chain.verifySwap(s.envelope, intent, limits, fresh);
        const freshBalances = await this.chain.balances(s.envelope, this.balanceTokens(limits));
        const finalViolations = policyViolations(limits, { token: intent.token, tokenOut: intent.tokenOut, amount: intent.amount, to: intent.to, swap: kind === "swap", slippage: intent.slippageBps, spend: validated.spend, used: journal.used(), balances: freshBalances, gasCost: validated.gasCost, fee: validated.op.maxFeePerGas, gasUnits: validated.gasUnits, gasToken: intent.gasToken, gasCharge: validated.gasCharge, calls: validated.calls });
        if (finalViolations.includes("exposure_limit") || (finalViolations.length && (!r.approval || r.approval.liveTest))) {
          r.reasons = finalViolations; delete r.approval; await journal.transition(r, "approval_required"); return result(r);
        }
        for (const [token, amount] of Object.entries(validated.spend)) if (BigInt(freshBalances[token] ?? "0") < BigInt(amount)) throw new WalletError("policy_denied", "Balance changed before signing");
        if (prepareOnly || (!this.signingEnabled && !this.liveTestApproved(s, r))) {
          r.reasons = ["release_test_approval_required"]; await journal.transition(r, "approval_required"); return result(r);
        }
        await this.canSubmit(s, r);
        if (r.approval && r.approval.expiresAt <= Date.now()) throw new WalletError("approval_required", "Exact-operation approval expired before signing");
        if (r.deadline && r.deadline <= Math.floor(Date.now() / 1000) + MIN_SWAP_REMAINING_SECONDS) throw new WalletError("validation_failed", "Swap deadline is too close");
        const privateKey = unlockWallet(this.ctx.config, s.envelope, s.wrappingKey);
        try {
          // viem requires a hex string; V8 cannot guarantee zeroization of that temporary.
          r.operation!.signature = await privateKeyToAccount(`0x${privateKey.toString("hex")}`).signMessage({ message: { raw: validated.hash } });
        } finally { privateKey.fill(0); }
        await this.canSubmit(s, r);
        await journal.transition(r, "signed"); // fsync completes before any submission.
      } catch (error) {
        if (r.status === "preparing") { r.lastError = error instanceof WalletError ? error.code : "validation_failed"; await journal.transition(r, "failed"); }
        if (error instanceof WalletError) throw error;
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
      if (r.reasons?.includes("exposure_limit")) throw new WalletError("policy_denied", "Change exposure limits interactively or reduce wallet funding first");
      if (liveTest && (r.intent.kind !== "transfer" || r.intent.gasToken !== "native" || r.replacement)) throw new WalletError("policy_denied", "Funded test approval only permits a transfer with native gas and no replacement");
      const state = await this.chain.state(s.envelope);
      const unsigned = { ...r.operation, signature: "0x" };
      const validated = validateOperation(this.ctx.config, s.envelope, r.intent, unsigned, { nonce: state.nonce, deployed: state.deployed, hash: r.userOpHash, deadline: r.deadline });
      if (r.intent.kind === "swap") await this.chain.verifySwap(s.envelope, r.intent, limits, state);
      if (liveTest) {
        const balances = await this.chain.balances(s.envelope, this.balanceTokens(limits)), used = journal.used();
        // An exact retry already owns this reservation; do not count it twice.
        if (ownsNonce(r.status)) for (const [token, amount] of Object.entries(r.reservation)) addSpend(used, token, -BigInt(amount));
        const violations = policyViolations(limits, { token: r.intent.token, amount: r.intent.amount, to: r.intent.to, swap: false, slippage: 0, spend: validated.spend, used, balances, gasCost: validated.gasCost, fee: validated.op.maxFeePerGas, gasUnits: validated.gasUnits, gasToken: r.intent.gasToken, gasCharge: validated.gasCharge, calls: validated.calls });
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

  async reviewReplacement(id: string) {
    return this.store.session(async s => {
      await this.enabled(s);
      const journal = await Journal.open(s); await this.reconcile(journal);
      const r = journal.data.records.find(r => r.requestId === id);
      if (!r || !ownsNonce(r.status) || r.replacement?.signed) throw new WalletError("operation_pending", "Replacement requires an unresolved original operation without a signed replacement");
      const state = await this.chain.state(s.envelope);
      const built = await this.chain.buildReplacement(s.envelope, r, state);
      const wire = userOpToJson(built.op);
      const validated = validateOperation(this.ctx.config, s.envelope, this.replacementIntent(s), wire, { nonce: BigInt(r.nonce!), deployed: state.deployed, hash: built.userOpHash });
      await this.chain.simulate(validated);
      r.replacement = { operation: wire, userOpHash: validated.hash, maxGasCost: validated.gasCost.toString(), signed: false, expiresAt: Date.now() + 300_000 };
      r.sequence = ++journal.data.sequence; await journal.save();
      return { wallet: publicWallet(s.envelope), records: [structuredClone(r)] };
    });
  }
  private replacementIntent(s: WalletSession): Intent {
    return { intentSchemaVersion: 1, kind: "transfer", token: "native", amount: "0", gasToken: "native", to: s.envelope.account, slippageBps: 0, feeTier: 3000 };
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
      const validated = validateOperation(this.ctx.config, s.envelope, this.replacementIntent(s), replacement.operation, { nonce: state.nonce, deployed: state.deployed, hash: replacement.userOpHash });
      if (validated.gasCost.toString() !== replacement.maxGasCost) throw new WalletError("validation_failed", "Replacement gas ceiling changed");
      await this.chain.simulate(validated);
      const balances = await this.chain.balances(s.envelope, ["native"]);
      if (BigInt(balances.native ?? "0") < validated.gasCost) throw new WalletError("policy_denied", "Native balance cannot cover the reviewed replacement gas");
      await this.canSubmit(s);
      if (replacement.expiresAt <= Date.now()) throw new WalletError("approval_required", "Replacement review expired before signing");
      const key = unlockWallet(this.ctx.config, s.envelope, s.wrappingKey);
      try { replacement.operation.signature = await privateKeyToAccount(`0x${key.toString("hex")}`).signMessage({ message: { raw: validated.hash } }); }
      finally { key.fill(0); }
      replacement.signed = true;
      // Keep the original reservation as well: either signed operation might win.
      addSpend(r.reservation, "native", validated.gasCost);
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
function result(r: OperationRecord) {
  const nativeGas = r.intent.gasToken === "native" && (r.status === "confirmed" || r.status === "reverted") && r.consumed?.native !== undefined
    ? (BigInt(r.consumed.native) - (r.status === "confirmed" && r.intent.token === "native" ? BigInt(r.intent.amount) : 0n)).toString() : undefined;
  return { request_id: r.requestId, intent: r.intent, status: r.status, user_op_hash: r.userOpHash, replacement_user_op_hash: r.replacement?.userOpHash, transaction_hash: r.transactionHash, actual_native_gas_cost_wei: nativeGas, reasons: r.status === "approval_required" ? r.reasons : undefined, attempts: r.attempts, last_error: ["confirmed", "reverted", "superseded"].includes(r.status) ? undefined : r.lastError };
}
