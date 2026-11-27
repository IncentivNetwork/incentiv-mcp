import { AGENT_LINK_MIN_SECONDS, assertRegistryApproved, isRegistryIntent, registryCapability, linkBlocker } from "../agent-registry.js";
import { randomBytes } from "node:crypto";
import { formatUnits, getAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { type Hex } from "viem";
import { z } from "zod";
import { X402_MIN_USDC_GAS } from "../setup-policy.js";
import { type Config } from "../config.js";
import { Ctx } from "../context.js";
import { NetworkError } from "../network.js";
import { BundlerUnavailableError, userOpToJson } from "../userop.js";
import { publicWallet, unlockWallet, WalletError } from "./keystore.js";
import { RpcDisagreementError } from "./errors.js";
import { localWalletStore, type WalletSession, type WalletStore } from "./store.js";
import { archivedSchema, Journal, digest, holdsMainNonce, intentSchema, ownsNonce, signedReplacements, terminal, type Intent, type OperationRecord } from "./journal.js";
import { addSpend, authorize, limitsSchema, newAdministration, policyViolations, registryParentAllowed, x402QuoteViolations, x402Violations, type Limits, type Spend } from "./policy.js";
import { MIN_SWAP_REMAINING_SECONDS, REORG_MARGIN_BLOCKS, SWAP_DEADLINE_SECONDS, WalletChain, isTransportFailure, type ChainState } from "./chain.js";
import { validateOperation } from "./validate.js";
import { httpsTransport, sentNothing, type HttpResponse, type HttpTransport } from "../x402/http.js";
import { incentivX402, parsePaymentRequired, paymentHeader, paymentNonceKey, selectRequirements, settlement, x402Config, X402_NETWORK, X402_SCHEME, type PaymentRequirements, type SettleResponse } from "../x402/protocol.js";
import { MAX_RESPONSE_BYTES, recordedUrl, responseContent, usdcAmount, USDC_DECIMALS, x402Request, type X402Request } from "../x402/request.js";

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
    const balances = await this.spendingBalances(journal, this.balanceTokens(limits), state), used = journal.used();
    if (ownsNonce(r.status)) for (const [token, amount] of Object.entries(r.reservation)) addSpend(used, token, -BigInt(amount));
    const policyInput = { ...this.registryPolicy(r.intent), token: r.intent.token, tokenOut: r.intent.tokenOut, amount: r.intent.amount, to: r.intent.to, swap: r.intent.kind === "swap", slippage: r.intent.slippageBps, spend: validated.spend, used, balances, gasCost: validated.gasCost, fee: validated.op.maxFeePerGas, gasUnits: validated.gasUnits, gasToken: r.intent.gasToken, gasCharge: validated.gasCharge, calls: validated.calls };
    const permitted = () => {
      const violations = policyViolations(limits, policyInput);
      if (violations.includes("exposure_limit") || (violations.length && (!this.approved(s, r) || r.approval?.liveTest))) throw new WalletError("policy_denied", "Current policy does not permit this signed operation; reservation preserved");
      if (r.approval && !this.approved(s, r)) throw new WalletError("approval_required", "Exact-operation approval expired or policy changed; reservation preserved");
    };
    permitted();
    if (!covers(balances, journal, validated.spend, r)) throw new WalletError("policy_denied", "Balance cannot cover input plus maximum gas beside other pending operations");
    if (state.fees.baseFeePerGas > validated.op.maxFeePerGas) throw new WalletError("validation_failed", "Gas fee no longer covers the current base fee");
    if (isRegistryIntent(r.intent)) await this.chain.verifyRegistry(s.envelope, r.intent, state).catch((error: unknown) => {
      // These signed bytes can never succeed, yet they still hold the nonce, so a fresh request would be refused until they are replaced.
      // Other refusals, such as an unverifiable read or a full parent, can clear, so the request stays retryable as it is.
      if (!(error instanceof WalletError) || !UNSENDABLE_REGISTRY_ERRORS.includes(error.code)) throw error;
      throw new WalletError(error.code, `${error.detail}. Signed request ${r.requestId} cannot be sent but still holds the account nonce, so first clear it with wallet operation resolve ${r.requestId} --replace in your local terminal${r.intent.kind === "link_agent" ? ", then use a fresh Portal approval with a new request ID" : ""}`);
    });
    if (r.intent.kind === "swap") await this.chain.verifySwap(s.envelope, r.intent, limits, state);
    await this.chain.simulate(validated).catch((error: unknown) => {
      // The same bytes may never pass again, for example once the paymaster stops accepting their gas payment, yet they still hold the nonce.
      if (!(error instanceof WalletError) || error.code !== "simulation_failed") throw error;
      throw new WalletError(error.code, `${error.detail}. Signed request ${r.requestId} still holds the account nonce. If retrying later does not help, clear it with wallet operation resolve ${r.requestId} --replace${r.intent.gasToken === "native" ? "" : " --native-gas"} in your local terminal`);
    });
    await this.chain.assertCanonicalSnapshot(state).catch(rethrowSnapshotError);
    await this.canSubmit(s, r);
    if (r.deadline && r.deadline <= Math.floor(Date.now() / 1000) + MIN_SWAP_REMAINING_SECONDS) throw new WalletError("operation_pending", `Operation deadline is too close; reconcile, or review a same-nonce replacement with wallet operation resolve ${r.requestId} --replace in your local terminal`);
    // Policy and approval expiry may pass during the reads above, so they are checked again with nothing awaited before the broadcast.
    permitted();
  }
  private spendingBalances(journal: Journal, tokens: string[], state?: ChainState): Promise<Spend> {
    return this.reconcileX402Settlements(journal, true, { tokens, state });
  }

  private async reconcileX402Settlements(journal: Journal, forSpending: boolean, spend?: { tokens: string[]; state?: ChainState }): Promise<Spend> {
    const recent = Date.now() - X402_RECONFIRM_MS;
    // A settlement past the reorg margin is marked final once, so it no longer needs the RPC on every wallet call.
    const settled = journal.data.records.filter(r => r.intent.kind === "x402_payment" && !r.settlementFinal
      && (r.settledBlock !== undefined || (r.consumedAt ?? 0) > recent)
      && r.nonce !== undefined && (r.status === "confirmed" || r.status === "reverted" || r.status === "superseded"));
    if (!settled.length && !spend) return {};
    const wallet = journal.session.envelope;
    // Reads can still show older, recorded settlements during an outage. Spending needs a fresh check because
    // a failing receipt or nonce read does not imply that balance reads and simulation are unavailable.
    const outage = Symbol("outage");
    const read = <T>(value: Promise<T>) => value.catch((error: unknown): never => {
      if (!forSpending && rpcFault(error) && settled.every(r => (r.consumedAt ?? 0) <= recent)) throw outage;
      // Every spend reads its balances here, so an x402 message only fits when x402 settlements were rechecked.
      if (settled.length) rethrowX402RecheckError(error);
      rethrowSnapshotError(error);
    });
    try {
      const snapshot = spend?.state ?? await read(this.chain.state(wallet));
      const { block } = snapshot;
      // Each settlement's lane nonce, and each settlement block's hash once, read through one bounded pool, so
      // the recheck before every spend stays quick without exceeding X402_SETTLEMENT_CONCURRENCY reads per provider.
      const height = (r: OperationRecord) => r.settledBlock === undefined ? undefined : BigInt(r.settledBlock);
      const heights = [...new Set(settled.flatMap(r => { const n = height(r); return n !== undefined && n <= block && r.settledBlockHash ? [n] : []; }))];
      const hashes = new Map<bigint, Hex>(), nonces = new Map<OperationRecord, bigint>();
      await pooled([
        ...heights.map(n => async () => { hashes.set(n, await read(this.chain.canonicalBlockHash(n))); }),
        ...settled.map(r => async () => { nonces.set(r, await read(this.chain.laneNonce(wallet, BigInt(r.nonce!) >> 64n, block))); }),
      ], X402_SETTLEMENT_CONCURRENCY);
      const checks = settled.map(r => {
        const settledBlock = height(r), nonce = BigInt(r.nonce!);
        const behind = settledBlock !== undefined && block < settledBlock;
        const hash = !behind && settledBlock !== undefined && r.settledBlockHash ? hashes.get(settledBlock) : undefined;
        const orphaned = behind || (hash !== undefined && hash.toLowerCase() !== r.settledBlockHash);
        // A lagging RPC also shows the lane unused, or a head below the settlement; the payment is held either way.
        return { r, reopen: nonces.get(r) === nonce || orphaned, final: settledBlock !== undefined && block >= settledBlock + REORG_MARGIN_BLOCKS };
      });
      // Use the same height for balances and nonce reads. Discard the whole read if its block changed,
      // before changing any reservation or marking a settlement final.
      const balances = await (spend ? this.chain.balances(wallet, spend.tokens, block) : Promise.resolve({}))
        .catch((error: unknown) => { throw rpcOutage(error); })
        .finally(() => read(this.chain.assertCanonicalSnapshot(snapshot)));
      let finalized = false;
      for (const { r, reopen, final } of checks) {
        if (reopen) await this.reopenX402Settlement(journal, r);
        // A reorg may have occurred while the wallet was idle. The settlement was verified above before its checks retire.
        else if (final) { r.settlementFinal = true; r.sequence = ++journal.data.sequence; finalized = true; }
      }
      if (finalized) await journal.save();
      return balances;
    } catch (error) {
      if (error !== outage) throw error;
      return {};
    }
  }

  private async reopenX402Settlement(journal: Journal, r: OperationRecord): Promise<void> {
    // consumedAt and settledBlockHash are kept: while the record is open they count for nothing, and if a lagging
    // RPC caused the reopen, the payment confirms again in the same block and keeps its original spend time.
    delete r.consumed;
    delete r.transactionHash;
    delete r.settledBlock;
    delete r.settlementFinal;
    delete r.searchedBlock;
    delete r.discoveredBlock;
    delete r.retryLogs;
    for (const replacement of [r.replacement, r.priorReplacement]) if (replacement) { delete replacement.searchedBlock; delete replacement.discoveredBlock; delete replacement.retryLogs; }
    const confirmed = r.status === "confirmed";
    r.lastError = confirmed ? "x402_confirmation_rolled_back" : "x402_settlement_rolled_back";
    const status = signedReplacements(r).length ? "superseding" : confirmed ? "submitted" : "submission_unknown";
    await journal.transition(r, status);
  }

  private async reconcile(journal: Journal, forSpending = false): Promise<void> {
    await this.reconcileX402Settlements(journal, forSpending);
    // Connections are permanent: an unlink an earlier build left awaiting approval can never be approved, so it is cancelled.
    for (const r of journal.data.records) if (r.intent.kind === "unlink_agent" && (r.status === "preparing" || r.status === "approval_required")) {
      delete r.approval; r.lastError = "registry_unlink_unsupported"; await journal.transition(r, "cancelled");
    }
    // Reconciliation runs at the start of a locked session, so an x402 payment still preparing was interrupted
    // before it was signed: nothing can send it, so it is closed.
    for (const r of journal.data.records) if (r.intent.kind === "x402_payment" && r.status === "preparing") { r.lastError = "x402_preparation_interrupted"; await journal.transition(r, "failed"); }
    // Signed payments share one account state read; each reads only its own lane at that block.
    let shared: Promise<ChainState> | undefined;
    const state = () => shared ??= this.chain.state(journal.session.envelope);
    for (const r of journal.data.records.filter(r => ownsNonce(r.status))) {
      if (r.status === "signed" && r.intent.kind === "x402_payment") await this.reconcileSignedX402(journal, r, state);
      if (r.status === "signed" || !ownsNonce(r.status)) continue;
      if (r.status === "submitting") await journal.transition(r, "submission_unknown");
      try {
        const searched = searchProgress(r);
        // Search each signed candidate independently. Report lookup failures only if none yields a receipt.
        let lookupFailure: { error: unknown } | undefined;
        const findReceipt = (record: OperationRecord) => this.chain.receipt(record).catch((error: unknown) => {
          if (!lookupFailure || error instanceof WalletError) lookupFailure = { error };
          return undefined;
        });
        const receipt = await findReceipt(r);
        // Search progress is kept, so a payment settled long ago is reached over several reconciliations.
        if (!receipt && searchProgress(r) !== searched) { r.sequence = ++journal.data.sequence; await journal.save(); }
        let superseded = false;
        // Each signed replacement is looked up, including a token-paid one a native replacement was reviewed over.
        for (const candidate of receipt ? [] : signedReplacements(r)) {
          // A replacement has its own search start and progress: the payment's say nothing about it.
          const lookup: OperationRecord = { ...r, operation: candidate.operation, userOpHash: candidate.userOpHash, replacement: candidate, transactionHash: undefined, fromBlock: candidate.fromBlock ?? r.fromBlock, searchedBlock: candidate.searchedBlock, discoveredBlock: candidate.discoveredBlock, retryLogs: candidate.retryLogs };
          const replaced = await findReceipt(lookup);
          if (!replaced && searchProgress(lookup) !== searchProgress(candidate)) {
            for (const key of ["searchedBlock", "discoveredBlock", "retryLogs"] as const) {
              if (lookup[key] === undefined) delete candidate[key]; else Object.assign(candidate, { [key]: lookup[key] });
            }
            r.sequence = ++journal.data.sequence; await journal.save();
          }
          if (!replaced) continue;
          const gasToken = candidate.gasToken ?? "native";
          const blockHash = replaced.blockHash?.toLowerCase() as Hex | undefined;
          r.consumed = gasToken === "native" ? { native: replaced.actualGasCost.toString() } : { [gasToken]: candidate.gasCharge! };
          r.consumedAt = sameSettlement(r, blockHash) ? r.consumedAt : Date.now(); r.transactionHash = replaced.transactionHash;
          if (replaced.blockNumber !== undefined) r.settledBlock = replaced.blockNumber.toString();
          if (blockHash) r.settledBlockHash = blockHash; else delete r.settledBlockHash;
          // A mined replacement consumes the nonce even if its execution reverted.
          await journal.transition(r, "superseded"); superseded = true; break;
        }
        if (superseded) continue;
        if (lookupFailure) throw lookupFailure.error;
        // For an x402 payment, submitted means the seller reported its settlement; keep that until the receipt shows.
        const settledBySeller = r.intent.kind === "x402_payment" && r.status === "submitted";
        if (!receipt) { if (r.status === "submitted" && !settledBySeller) await journal.transition(r, "submission_unknown"); continue; }
        const spend: Spend = {};
        if (receipt.success) addSpend(spend, r.intent.token, BigInt(r.intent.amount));
        // Token-paymaster refunds are not inferred from an untrusted relay. Retain the
        // full authorized token payment conservatively, including reverted operations.
        const input = r.intent.token === r.intent.gasToken ? BigInt(r.intent.amount) : 0n;
        // If the original wins, release the unused replacements' gas reservations.
        const replacementGas = signedReplacements(r).filter(x => (x.gasToken ?? "native") === r.intent.gasToken)
          .reduce((sum, x) => sum + BigInt(x.gasCharge ?? x.maxGasCost), 0n);
        const gas = r.intent.gasToken === "native" ? receipt.actualGasCost : BigInt(r.reservation[r.intent.gasToken] ?? "0") - input - replacementGas;
        if (gas < 0n) throw new WalletError("wallet_recovery_required", "Invalid persisted gas reservation");
        addSpend(spend, r.intent.gasToken, gas);
        if (receipt.registryError) r.lastError = receipt.registryError;
        const blockHash = receipt.blockHash?.toLowerCase() as Hex | undefined;
        r.consumed = spend; r.consumedAt = sameSettlement(r, blockHash) ? r.consumedAt : Date.now(); r.transactionHash = receipt.transactionHash;
        if (receipt.blockNumber !== undefined) r.settledBlock = receipt.blockNumber.toString();
        if (blockHash) r.settledBlockHash = blockHash; else delete r.settledBlockHash;
        await journal.transition(r, receipt.success ? "confirmed" : "reverted");
      } catch (error) {
        if (error instanceof WalletError) throw error;
        if (r.status === "submitted" && r.intent.kind !== "x402_payment") await journal.transition(r, "submission_unknown");
      }
    }
    await compactX402(journal);
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
    this.refuseUnlink(r);
    await this.canSubmit(s, r);
    if (!r.operation || !r.userOpHash) throw new WalletError("wallet_recovery_required", "Signed operation is missing");
    if (r.deadline && r.deadline <= Math.floor(Date.now() / 1000)) throw new WalletError("operation_pending", `Signed operation deadline expired; review a same-nonce replacement with wallet operation resolve ${r.requestId} --replace in your local terminal`);
    // A registry request signed under pins this release no longer approves, or before a release without the registry,
    // cannot be sent; approving new pins waits for its nonce, so only a same-nonce replacement clears it.
    if (isRegistryIntent(r.intent)) try { assertRegistryApproved(this.ctx.config, s.envelope); } catch (error) {
      if (!(error instanceof WalletError)) throw error;
      if (error.code === "capability_manifest_unapproved") throw new WalletError(error.code, `Registry request ${r.requestId} was signed before this release changed the Agent Registry pins, so it cannot be sent. Clear it with wallet operation resolve ${r.requestId} --replace in your local terminal, then run wallet capabilities approve`);
      if (error.code === "registry_unavailable") throw new WalletError(error.code, `Registry request ${r.requestId} was signed, but this release does not include the Agent Registry, so it cannot be sent. Clear it with wallet operation resolve ${r.requestId} --replace in your local terminal`);
      throw error;
    }
    // An RPC or bundler outage while rechecking says nothing about the signed bytes, so the same request ID stays usable.
    const recheck = () => this.revalidate(s, journal, r).catch((error: unknown) => { throw rpcOutage(error); });
    await recheck();
    // Reconcile happened under the same cross-process lock before this retry.
    const prior = r.status as "signed" | "submission_unknown";
    r.attempts++;
    await journal.transition(r, "submitting");
    // Only a check that refused is known to have sent nothing; any other failure may follow a broadcast.
    let refusal: { error: unknown } | undefined;
    const check = async (step: () => Promise<void>) => { try { await step(); } catch (error) { refusal = { error }; throw error; } };
    try {
      await check(() => this.canSubmit(s, r));
      const returned = await this.chain.relay(r.operation, () => check(recheck));
      if (returned !== r.userOpHash) throw new Error();
    } catch {
      // The request keeps its state, and the refusal keeps its own guidance, such as how to replace bytes that can never land.
      if (refusal) { r.attempts--; await journal.transition(r, prior); throw refusal.error; }
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
      const intent = intentSchema.parse(await this.chain.normalize(kind, args).catch((error: unknown) => { throw rpcOutage(error); }));
      let r = journal.data.records.find(r => r.requestId === requestId);
      if ((r && r.intentHash !== digest(intent)) || (!r && (journal.data.probes?.some(p => p.requestId === requestId) || journal.data.archived?.some(a => a.requestId === requestId)))) throw new WalletError("idempotency_conflict", "This request ID is permanently bound to a different intent");
      // A finished request is returned as it is; only work that can still spend needs the strict settlement recheck.
      if (r && terminal(r.status)) return result(r);
      await this.reconcile(journal, true);
      // Reconciliation may have just settled it, so it is returned rather than prepared again.
      if (r && terminal(r.status)) return result(r);
      if (r && ownsNonce(r.status)) {
        if (prepareOnly) return result(r);
        if (r.status === "superseding") await this.submitReplacement(s, journal, r);
        else if (r.status === "signed" || r.status === "submission_unknown") await this.submit(s, journal, r);
        if (args.wait_for_confirmation === true) await this.reconcile(journal);
        return result(r);
      }
      const holder = journal.data.records.find(holdsMainNonce);
      if (holder) throw mainNoncePending(holder, "retry this request");
      // Only x402 payments, on their own lanes, can be pending here. Read the chain only when one is.
      if (journal.data.records.some(o => ownsNonce(o.status))) assertDeploysOnce((await this.chain.state(s.envelope).catch((error: unknown) => { throw rpcOutage(error); })).deployed, journal);
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
        const balances = await this.spendingBalances(journal, this.balanceTokens(limits), state);
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
        if (!covers(balances, journal, validated.spend, r)) throw new WalletError("policy_denied", "Insufficient input balance plus maximum gas payment beside other pending operations");
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
        const freshBalances = await this.spendingBalances(journal, this.balanceTokens(limits), fresh);
        const finalViolations = policyViolations(limits, { ...this.registryPolicy(intent), token: intent.token, tokenOut: intent.tokenOut, amount: intent.amount, to: intent.to, swap: kind === "swap", slippage: intent.slippageBps, spend: validated.spend, used: journal.used(), balances: freshBalances, gasCost: validated.gasCost, fee: validated.op.maxFeePerGas, gasUnits: validated.gasUnits, gasToken: intent.gasToken, gasCharge: validated.gasCharge, calls: validated.calls });
        if (finalViolations.includes("exposure_limit") || (finalViolations.length && (!r.approval || r.approval.liveTest))) {
          r.reasons = finalViolations; delete r.approval; await journal.transition(r, "approval_required"); return result(r);
        }
        if (!covers(freshBalances, journal, validated.spend, r)) throw new WalletError("policy_denied", "Balance changed before signing");
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
        const mapped = rpcOutage(error), failure = mapped instanceof WalletError ? mapped : undefined;
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
        // An archived record is an x402 payment, which a request ID bound to this intent never is.
        response = await this.operation(requestId) as typeof response;
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
      const url = this.agentLinkUrl(s);
      // A Portal approval for a wallet that cannot sign is unusable, so the user is not asked for one.
      try {
        const limits = await this.linkPolicy(s);
        assertOutlastsApproval(limits);
        if (!this.signingEnabled) throw new WalletError("wallet_release_unreviewed", "This release has candidate signing disabled, so it cannot send link_agent. Use a release with signing enabled to connect this agent");
        // Local refusals come before any registry read, so they hold whatever the RPC does.
        assertRegistryApproved(this.ctx.config, s.envelope);
        if (!limits.agentRegistry?.parents.length) throw new WalletError("registry_parent_not_allowed", "Local wallet policy allows no Portal account to connect this agent. Add one with incentiv-mcp setup in your local terminal, then call prepare_agent_link again");
        // link_agent refuses a new request while another operation holds the nonce, and a Portal approval lasts minutes.
        const journal = await Journal.open(s); await this.reconcile(journal);
        const holder = journal.data.records.find(holdsMainNonce);
        if (holder) throw mainNoncePending(holder, "call prepare_agent_link again");
        const status = await this.chain.registryStatus(s.envelope);
        const blocked = linkBlocker(status, status.deployed);
        if (blocked) return linkRefusal(status, blocked);
        // A pending payment would deploy an undeployed agent, and link_agent refuses to deploy it a second time.
        assertDeploysOnce(status.deployed, journal);
        // The policy can expire during the registry read.
        assertOutlastsApproval(await this.linkPolicy(s));
        return { ...status, portal_url: url.href, next_action: APPROVAL_FLOW };
      } catch (error) {
        if (error instanceof WalletError && ["policy_not_configured", "wallet_locked", "policy_expired", "capability_manifest_unapproved", "registry_parent_not_allowed", "wallet_release_unreviewed", "operation_pending"].includes(error.code)) return linkRefusal({ agent: s.envelope.account }, [error.code, error.detail]);
        throw error;
      }
    });
  }
  private async linkPolicy(s: WalletSession): Promise<Limits> {
    const limits = await this.enabled(s);
    if (limits.expiresAt && limits.expiresAt <= Date.now()) throw new WalletError("policy_expired", "Local wallet policy has expired. Renew it with incentiv-mcp setup in your local terminal");
    return limits;
  }
  /**
   * The local conditions for signing link consent to `parent`, each refused with a WalletError: an enabled
   * policy that allows the parent, a release that may sign, an approved registry capability, and no
   * registry request that may still land. Requests that only await approval are returned as `queued`.
   */
  private async linkConsentChecks(s: WalletSession, parent: string) {
    const limits = await this.linkPolicy(s);
    if (!registryParentAllowed(limits, parent)) throw new WalletError("registry_parent_not_allowed", "Local wallet policy does not allow this parent. Add it with incentiv-mcp setup in your local terminal, then call sign_agent_link again");
    if (!this.signingEnabled) throw new WalletError("wallet_release_unreviewed", "This release has candidate signing disabled, so it cannot sign link consent or send link_agent. Use a release with signing enabled to connect this agent");
    assertRegistryApproved(this.ctx.config, s.envelope);
    // Settle requests that already landed, so a confirmed link is not reported as still unresolved.
    const journal = await Journal.open(s); await this.reconcile(journal);
    const registry = journal.data.records.filter(r => isRegistryIntent(r.intent) && !terminal(r.status));
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
    // The request goes out from this computer and the endpoint may act on it, so x402 must be on and the site allowed.
    const { pending } = await this.store.session(async s => {
      await s.assertOwned();
      const policy = s.envelope.policy;
      if (!policy.configured) throw new WalletError("policy_not_configured", "Run incentiv-mcp setup in your local terminal; nothing was sent");
      if (!policy.enabled || await s.disabled()) throw new WalletError("wallet_locked", "Wallet is disabled, so it sends no x402 requests; local administration authorization is required. Nothing was sent");
      assertPolicyLive(policy.limits, "nothing was sent");
      if (!policy.limits.x402) throw new WalletError("policy_denied", "x402 payments are off in local wallet policy, so this wallet sends no x402 requests; the user can enable them with incentiv-mcp setup");
      if (x402Violations(policy.limits, req.origin, ZERO_ADDRESS, "0").includes("x402_origin_not_allowed")) throw new WalletError("policy_denied", "Local wallet policy does not allow this site for x402, so nothing was sent");
      // Start the request while the policy is still locked. Release the wallet before waiting on the seller.
      const pending = this.http({ ...req, maxBytes: MAX_RESPONSE_BYTES, timeoutMs: UNPAID_REQUEST_TIMEOUT_MS })
        .then(response => ({ response }), (error: unknown) => ({ error }));
      return { pending };
    });
    const result = await pending;
    if ("error" in result) throw result.error;
    const { response } = result;
    if (httpSucceeded(response.status) && !response.incomplete) return { url: req.url, payment_required: false, content: responseContent(response), next_action: "This request needs no payment; its answer is in content." };
    if (response.status !== 402) return { url: req.url, ...unpaidHttpFailure(response) };
    const required = parsePaymentRequired(response);
    let accepted: PaymentRequirements | undefined, unsupported: string | undefined;
    try { accepted = selectRequirements(required, this.ctx.config); }
    catch (error) { if (!(error instanceof WalletError)) throw error; unsupported = error.detail; }
    // Select and assess the offer under the same policy, which may have changed while the seller was answering.
    const reasons = accepted ? await this.store.session(async s => {
      const policy = s.envelope.policy;
      if (!policy.configured) return ["policy_not_configured"];
      const disabled = !policy.enabled || await s.disabled();
      const usdc = x402Config(this.ctx.config).usdc;
      const violations = (o: PaymentRequirements) => x402QuoteViolations(policy.limits, usdc, req.origin, o.payTo, o.amount);
      accepted = selectRequirements(required, this.ctx.config, o => !violations(o).length);
      const reasons = violations(accepted);
      return disabled ? ["wallet_disabled", ...reasons] : reasons;
    }).catch(() => ["wallet_unavailable"]) : undefined;
    return {
      url: req.url, payment_required: true, payable: !!accepted, ...(unsupported ? { unsupported } : {}),
      ...(accepted ? { price: { amount: formatUnits(BigInt(accepted.amount), USDC_DECIMALS), amount_atomic: accepted.amount, asset: "USDC", pay_to: getAddress(accepted.payTo), scheme: accepted.scheme, network: accepted.network, max_timeout_seconds: accepted.maxTimeoutSeconds, settles_before_handler: accepted.extra?.paymentFlow === "upfront" } } : {}),
      gas: `Paid on top of the price: about 0.03 USDC through the paymaster (minimum ${formatUnits(X402_MIN_USDC_GAS, USDC_DECIMALS)}), or CENT with gas_token native.`,
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
    // A chain read that fails while a payment is checked or recovered is an RPC outage, not wallet damage.
    return this.store.session(async s => this.payX402In(s, requestId, req, request, maxAmount, gasToken).catch((error: unknown) => {
      if (isTransportFailure(error)) throw new WalletError("rpc_unavailable", "Could not read chain state from RPC; retry with the same request ID");
      throw error;
    }));
  }
  private async payX402In(s: WalletSession, requestId: string, req: X402Request, request: Hex, maxAmount: bigint, gasToken: string) {
    const cfg = this.ctx.config, xcfg = x402Config(cfg);
    const limits = await this.enabled(s);
    const journal = await Journal.open(s); await this.reconcile(journal, true);
    const archived = journal.data.archived?.find(a => a.requestId === requestId);
    if (archived) {
      if (archived.request !== request) throw new WalletError("idempotency_conflict", "This request ID is permanently bound to a different request");
      const paid = archived.status === "confirmed";
      return { request_id: requestId, status: archived.status, user_op_hash: archived.userOpHash, transaction_hash: archived.transactionHash, last_error: archivedError(archived), archived: true, content_delivered: false,
        next_action: paid
          ? "This payment settled and its record is archived, so its answer is no longer available. Buying again with a new request ID pays again."
          // Any outcome other than confirmed (never sent, expired, cancelled, reverted) left the seller unpaid.
          : `This request ID's payment ended as ${archived.status}${archivedError(archived) ? ` (${archivedError(archived)})` : ""} without paying the seller, and its record is archived. This retry sent no payment. Use a new request ID to try again.` };
    }
    const existing = journal.data.records.find(r => r.requestId === requestId);
    if (existing) {
      if (existing.intent.kind !== "x402_payment" || existing.intent.x402!.request !== request) {
        // A changed argument must not lead the agent to a new request ID while the bound payment can still settle.
        // A signed payment never left this computer and expires unpaid.
        const pending = existing.intent.kind === "x402_payment" && ownsNonce(existing.status) && existing.status !== "signed";
        throw new WalletError("idempotency_conflict", pending
          ? `This request ID is bound to a different request, whose payment is ${existing.status} and may still settle. Check get_agent_operation before buying again under a new request ID. ${X402_UNKNOWN_ACTION(existing.requestId)}`
          : "This request ID is permanently bound to a different request");
      }
      // Any send needs current wallet policy (checked in deliverX402): even after an uncertain attempt, the seller
      // may never have received the signature. A payment the seller may hold is resent unchanged.
      if (existing.status === "signed") return this.deliverX402(s, journal, existing, req, limits);
      if (existing.status === "submission_unknown") {
        // The seller may already have run a POST it received; sending it again could run it twice.
        if (!replayable(req)) return { ...x402Result(existing), content_delivered: false, next_action: `The seller may already have received and acted on this POST, so this wallet does not send it again without an Idempotency-Key header. ${X402_UNKNOWN_ACTION(existing.requestId)}` };
        return this.deliverX402(s, journal, existing, req, limits);
      }
      // Whether an answer handed back earlier reached the caller is unknown here, so a retry may ask the seller again.
      if (existing.status === "submitted" || existing.status === "confirmed") return this.redeliverX402(s, journal, existing, req, limits);
      // Either the payment or its cancellation will take the nonce lane; a new request ID uses another lane, so both could pay.
      if (existing.status === "superseding") return { ...x402Result(existing), next_action: `A cancellation of this payment is pending, and the payment itself may still settle instead. Check get_agent_operation and wait until it shows superseded (cancelled, nothing paid), reverted (the payment failed on chain, so the seller was not paid) or confirmed (paid; ${answerAdvice(req)}). Buying again with a new request ID before then may pay twice.` };
      return { ...x402Result(existing), next_action: "Use a new request ID to try again." };
    }
    if (!limits.x402) throw new WalletError("policy_denied", "x402 payments are off in local wallet policy; the user can enable them with incentiv-mcp setup");
    const early = x402Violations(limits, req.origin, "0x0000000000000000000000000000000000000000", "0").filter(r => r !== "x402_pay_to_not_allowed");
    if (early.length) throw new WalletError("policy_denied", `Local wallet policy refuses this resource: ${early.join(", ")}`);

    // Bind every unpaid POST before sending. Even with a seller-side key, only an identical request can replay safely.
    const probe = journal.data.probes?.find(p => p.requestId === requestId);
    if (probe) {
      // A valid 402 shows the resource did not act on the POST, so that binding may change, say to a higher max_amount, as a GET's can.
      if (probe.request !== request && probe.outcome !== "payment_required") throw new WalletError("idempotency_conflict", "This request ID is permanently bound to a different request");
      if (!replayable(req) && probe.outcome === "not_required") return { request_id: requestId, status: "not_required", content_delivered: false, next_action: "This POST was already sent under this request ID and needed no payment; its answer was returned then. This wallet does not send it again: use a new request ID to send it again." };
      if (!replayable(req) && probe.outcome === "sending") throw new WalletError("x402_request_uncertain", "This POST may already have reached the resource under this request ID, which may have acted on it. Nothing was paid. This wallet does not send it again: use a new request ID to send it again.");
    }
    const bind = async (outcome: "sending" | "payment_required" | "not_required" | undefined, at = Date.now(), bound: string = request) => {
      if (req.method !== "POST") return;
      journal.data.probes = (journal.data.probes ?? []).filter(p => p.requestId !== requestId);
      // A binding that may guard an acted-on POST is never dropped, so their number is capped instead.
      if (outcome === "sending" && journal.data.probes.length >= MAX_PROBES) throw new WalletError("policy_denied", `This wallet already keeps ${MAX_PROBES} unpaid POST requests bound to their request IDs, so it cannot bind a new POST request ID; nothing was sent or paid. The user can clear old bindings with incentiv-mcp wallet x402 clear-bindings in their own terminal`);
      if (outcome) journal.data.probes.push({ requestId, request: bound, outcome, at });
      await journal.save();
    };
    assertPolicyLive(limits, "nothing was sent or paid");
    if (probe?.outcome !== "not_required") await bind("sending");
    // The earlier binding comes back as it was, its own request included.
    const restoreProbe = () => bind(probe?.outcome, probe?.at, probe?.request);
    // An unpaid request can still have side effects. Check again after the durable POST binding.
    try {
      await s.assertOwned();
      await this.enabled(s);
      assertPolicyLive(limits, "nothing was sent or paid");
    } catch (error) {
      await restoreProbe();
      throw error;
    }
    const unpaid = await this.http({ ...req, maxBytes: MAX_RESPONSE_BYTES, timeoutMs: UNPAID_REQUEST_TIMEOUT_MS }).catch(async (error: unknown) => {
      // If nothing was sent, restore the earlier binding. Otherwise the resource may have acted on the request.
      if (neverSent(error)) await restoreProbe();
      if (error instanceof WalletError) throw error;
      const uncertain = !neverSent(error) && !replayable(req) ? " The resource may have received this POST, so this wallet does not send it again under this request ID." : "";
      throw new WalletError("x402_request_failed", `The resource could not be reached, so nothing was paid: ${error instanceof Error ? error.message.slice(0, 200) : "unknown error"}.${uncertain}`);
    });
    if (httpSucceeded(unpaid.status) && !unpaid.incomplete) {
      await bind("not_required");
      return { request_id: requestId, status: "not_required", content: responseContent(unpaid), next_action: "No payment was needed or made." };
    }
    if (unpaid.status !== 402) {
      // An HTTP error or redirect can follow a POST side effect. Keep its existing uncertain binding.
      const failure = unpaidHttpFailure(unpaid);
      const nextAction = replayable(req) ? failure.next_action : `${failure.next_action} The resource may already have acted on this POST, so the wallet keeps its request ID bound.`;
      return { request_id: requestId, ...failure, next_action: nextAction };
    }
    // Only a valid x402 challenge shows the resource did not act on the request; a plain 402 may follow a side
    // effect, so the binding stays uncertain if it is not one.
    const required = parsePaymentRequired(unpaid);
    // A challenge on a later retry says nothing about an earlier POST that might have run for free.
    if (probe && probe.outcome !== "payment_required") {
      await restoreProbe();
      if (probe.outcome === "not_required") return { request_id: requestId, status: "not_required", content_delivered: false, next_action: "This POST previously needed no payment. The seller asked for payment on this retry, so the wallet did not pay or recover its answer." };
      throw new WalletError("x402_request_uncertain", "The seller asked for payment on this retry, but it may have acted on the earlier unpaid POST. Nothing was paid. Check the seller's result before making a new request.");
    }
    await bind("payment_required");
    // The cheapest option within max_amount that local policy allows; failing that, the cheapest, whose refusal says why.
    const accepted = selectRequirements(required, cfg, o => BigInt(o.amount) <= maxAmount && !x402QuoteViolations(limits, xcfg.usdc, req.origin, o.payTo, o.amount).length);
    const amount = BigInt(accepted.amount);
    if (amount > maxAmount) throw new WalletError("x402_price_above_max", `The resource asks ${formatUnits(amount, USDC_DECIMALS)} USDC, above max_amount ${formatUnits(maxAmount, USDC_DECIMALS)}; nothing was paid`);
    const payTo = getAddress(accepted.payTo).toLowerCase();
    const refused = x402Violations(limits, req.origin, payTo, accepted.amount);
    if (refused.length) throw new WalletError("policy_denied", `Local wallet policy refuses this payment: ${refused.join(", ")}; nothing was paid`);
    // Refusals that need no built operation (the price against USDC limits, exposure and the balance) come before
    // anything is journaled, so an agent retrying a refused purchase under new request IDs cannot fill the journal.
    // The unpaid request can take a while; a settlement rolled back meanwhile must hold its reservation again
    // before the balance is counted, or the restored funds would pay twice.
    const state = await this.chain.state(s.envelope).catch(rethrowSnapshotError);
    const balances = await this.spendingBalances(journal, this.balanceTokens(limits), state);
    assertDeploysOnce(state.deployed, journal);
    const price: Spend = { [xcfg.usdc.toLowerCase()]: accepted.amount };
    const priced = policyViolations(limits, { token: xcfg.usdc.toLowerCase(), amount: accepted.amount, swap: false, slippage: 0, spend: price, used: journal.used(), balances, gasCost: 0n, fee: 0n, gasUnits: 0n, gasToken, gasCharge: 0n, calls: [], x402: { origin: req.origin, payTo } });
    if (priced.length) throw new WalletError("policy_denied", `Local wallet policy refuses this payment: ${priced.join(", ")}; nothing was paid`);
    if (!covers(balances, journal, price)) throw new WalletError("policy_denied", "Balance cannot cover the price beside other pending operations; nothing was paid");

    const paymentId = `0x${randomBytes(32).toString("hex")}` as Hex;
    const validUntil = Math.floor(Date.now() / 1000) + accepted.maxTimeoutSeconds;
    // The seller chooses the size of its terms; terms too large to journal are its error, not this wallet's.
    const parsed = intentSchema.safeParse({
      intentSchemaVersion: 1, kind: "x402_payment", token: xcfg.usdc.toLowerCase(), amount: accepted.amount, gasToken, to: payTo, slippageBps: 0, feeTier: 3000,
      x402: { url: recordedUrl(req.url), origin: req.origin, method: req.method, request, maxAmount: maxAmount.toString(), accepted: JSON.stringify(accepted), ...(required.resource ? { resource: JSON.stringify(required.resource) } : {}), paymentId, validUntil },
    });
    if (!parsed.success) throw new WalletError("x402_invalid_response", "The resource's payment terms or URL are too large to record; nothing was paid");
    const intent = parsed.data;
    // The payment record now binds the request ID; its probe is no longer needed.
    if (journal.data.probes) journal.data.probes = journal.data.probes.filter(p => p.requestId !== requestId);
    // Past this size, new payments wait so that transfers and recovery always have room; old ones are archived over time.
    if (journal.bytes > X402_JOURNAL_BYTES) throw new WalletError("policy_denied", "The wallet's operation history is nearly full, so x402 payments pause; transfers still work. Nothing was paid. The user can free room by clearing old archived payments with incentiv-mcp wallet x402 clear-archive in their own terminal");
    const r = await journal.create(requestId, intent);
    try {
      const key = paymentNonceKey(paymentId, validUntil);
      const [laneNonce, x402] = await Promise.all([this.chain.laneNonce(s.envelope, key, state.block), this.x402Loader()]);
      // Built like a transfer, so the USDC gas fee follows the pinned paymaster's fee schedule (the reference
      // client in @incentiv/x402 0.1.1 prices it from a CENT quote instead). It then has to pass that package's
      // own check of the SPEC 4.3 shape, and this wallet's validator.
      const prepared = await this.chain.build(s.envelope, intent, { ...state, nonce: laneNonce }).catch((error: unknown) => {
        if (error instanceof WalletError || isTransportFailure(error) || error instanceof BundlerUnavailableError) throw error;
        throw new WalletError("validation_failed", `Could not prepare the payment: ${error instanceof Error ? error.message.slice(0, 300) : "unknown error"}`);
      });
      try { x402.checkPaysRequirements(x402.decodePaymentOp(prepared.op as Parameters<typeof x402.decodePaymentOp>[0], xcfg), accepted); }
      catch { throw new WalletError("validation_failed", "The prepared payment does not pay exactly what the resource asked"); }
      const wire = userOpToJson(prepared.op);
      const validated = validateOperation(cfg, s.envelope, intent, wire, { nonce: laneNonce, deployed: state.deployed, hash: prepared.userOpHash });
      const used = journal.used();
      const violations = policyViolations(limits, { token: intent.token, amount: intent.amount, swap: false, slippage: 0, spend: validated.spend, used, balances, gasCost: validated.gasCost, fee: validated.op.maxFeePerGas, gasUnits: validated.gasUnits, gasToken, gasCharge: validated.gasCharge, calls: validated.calls, x402: { origin: req.origin, payTo } });
      if (violations.length) { r.reasons = violations; throw new WalletError("policy_denied", `Local wallet policy refuses this payment: ${violations.join(", ")}; nothing was paid`); }
      if (!covers(balances, journal, validated.spend)) throw new WalletError("policy_denied", "Balance cannot cover the price plus the maximum gas payment beside other pending operations; nothing was paid");
      r.operation = wire; r.userOpHash = validated.hash; r.nonce = laneNonce.toString(); r.deadline = validUntil; r.reservation = validated.spend; r.fromBlock = state.block.toString();
      await this.chain.simulate(validated);
      await this.chain.assertCanonicalSnapshot(state).catch(rethrowSnapshotError);
      if (validUntil <= Math.floor(Date.now() / 1000) + 5) throw new WalletError("validation_failed", "The seller's payment window closed while the payment was prepared; retry with a new request ID");
      assertPolicyLive(limits, "it expired while the payment was prepared; nothing was paid");
      await this.canSubmit(s, r);
      r.operation.signature = await this.signRaw(s, validated.hash);
      await this.canSubmit(s, r);
      await journal.transition(r, "signed"); // fsync completes before the payment leaves this computer.
    } catch (error) {
      // The record is closed below, so an outage, here or in the simulation, is retried under a new request ID.
      const mapped = rpcOutage(error);
      const failure = mapped instanceof WalletError && mapped.code === "rpc_unavailable" ? new WalletError("rpc_unavailable", "Could not reach the RPC or bundler while preparing the payment, so nothing was paid; retry with a new request ID")
        : mapped instanceof WalletError ? mapped : undefined;
      if (r.status === "preparing") { r.lastError = failure?.code ?? "validation_failed"; await journal.transition(r, "failed"); }
      if (failure) throw failure;
      throw new WalletError("validation_failed", "Local x402 payment preparation failed");
    }
    return this.deliverX402(s, journal, r, req, limits, true);
  }

  /**
   * Sending a signed payment may release it to the seller for the first time, even after an uncertain attempt, so
   * every send must still pass current wallet policy, balance and its nonce lane, as it did when signed. Its own
   * reservation is excluded from what is already used. A refusal sends nothing and keeps the record as it was.
   */
  private async recheckX402(s: WalletSession, journal: Journal, r: OperationRecord, limits: Limits, consequence: string, freshlySimulated: boolean): Promise<ChainState> {
    const state = await this.chain.stateFor(s.envelope, r).catch(rethrowSendCheckError);
    if (state.nonce !== BigInt(r.nonce!)) throw new WalletError("operation_pending", "This payment's nonce lane has moved; check get_agent_operation");
    const validated = validateOperation(this.ctx.config, s.envelope, r.intent, { ...r.operation!, signature: "0x" }, { nonce: state.nonce, deployed: state.deployed, hash: r.userOpHash! });
    if (digest(validated.spend) !== digest(r.reservation)) throw new WalletError("wallet_recovery_required", "Operation reservation does not match the signed spend");
    const balances = await this.spendingBalances(journal, this.balanceTokens(limits), state).catch(rethrowSendCheckError), used = journal.used();
    for (const [token, amount] of Object.entries(r.reservation)) addSpend(used, token, -BigInt(amount));
    const violations = policyViolations(limits, { token: r.intent.token, amount: r.intent.amount, swap: false, slippage: 0, spend: validated.spend, used, balances, gasCost: validated.gasCost, fee: validated.op.maxFeePerGas, gasUnits: validated.gasUnits, gasToken: r.intent.gasToken, gasCharge: validated.gasCharge, calls: validated.calls, x402: { origin: r.intent.x402!.origin, payTo: r.intent.to! } });
    if (violations.length) throw new WalletError("policy_denied", `Local wallet policy no longer allows this payment: ${violations.join(", ")}; ${consequence}`);
    if (!covers(balances, journal, validated.spend, r)) throw new WalletError("policy_denied", `Balance no longer covers this payment beside other pending operations; ${consequence}`);
    if (state.fees.baseFeePerGas > validated.op.maxFeePerGas) throw new WalletError("validation_failed", `The signed gas fee no longer covers the current base fee; ${consequence}`);
    // A persisted payment may have been simulated against older TransferGate rules or paymaster terms.
    if (!freshlySimulated) await this.chain.simulate(validated).catch((error: unknown) => {
      if (error instanceof WalletError && error.code === "simulation_failed") throw new WalletError(error.code, `${error.detail}; ${consequence}`);
      throw rpcOutage(error);
    });
    return state;
  }

  /**
   * The seller reported or the chain shows this payment settled, but its answer may not have reached the caller:
   * the process can stop after the answer is recorded and before the tool returns. For a GET, or a POST that
   * carries an Idempotency-Key, the same signed payment is offered to the seller once more; it owns one nonce, so
   * it cannot be charged again, and the seller may serve it. Any other POST is never repeated: a seller that
   * accepts the payment again would run its handler a second time.
   */
  private async redeliverX402(s: WalletSession, journal: Journal, r: OperationRecord, req: X402Request, limits: Limits) {
    const x = r.intent.x402!;
    let response: Awaited<ReturnType<typeof this.http>> | undefined;
    // Neither a seller's report nor a confirmation the chain later drops is proof: while the nonce is unused, the
    // seller could still submit the payment, so sending it again would be a send under no current policy.
    const state = await this.chain.stateFor(s.envelope, r).catch(rethrowSnapshotError);
    if (state.nonce === BigInt(r.nonce!)) {
      // Past the reorg margin a settlement is not rechecked, so an unused lane only means this RPC is behind.
      if (r.status === "confirmed" && r.settlementFinal) throw new WalletError("rpc_unavailable", "The RPC shows this settled payment's nonce as unused, so it is behind; retry this request ID later. Nothing more was paid");
      if (r.status === "confirmed") {
        await this.chain.assertCanonicalSnapshot(state).catch(rethrowSnapshotError);
        await this.reopenX402Settlement(journal, r);
      }
      return { ...x402Result(r), content_delivered: false, next_action: `${r.lastError === "x402_confirmation_rolled_back" ? "The RPC no longer shows this payment's settlement: the chain reorganized, or the RPC is behind" : "The seller reported settling this payment, but it is not on chain yet"}, so this wallet does not send it again. Check get_agent_operation before buying again; once it shows confirmed, ${answerAdvice(req)}. Nothing more was paid. ${X402_UNKNOWN_ACTION(r.requestId)}` };
    }
    if (replayable(req)) {
      // Asking again sends a request from this computer, so it needs current policy like any other x402 request.
      // The payment itself has settled, so a refusal only withholds the answer.
      await this.chain.assertCanonicalSnapshot(state).catch(rethrowSnapshotError);
      await s.assertOwned(); await this.enabled(s);
      const refused = !limits.x402 ? "x402 payments are now off in local wallet policy"
        : x402Violations(limits, req.origin, ZERO_ADDRESS, "0").includes("x402_origin_not_allowed") ? "local wallet policy no longer allows this site"
        : limits.expiresAt && Date.now() >= limits.expiresAt ? "local wallet policy expired" : undefined;
      if (refused) return { ...x402Result(r), content_delivered: false, next_action: `This payment ${r.status === "confirmed" ? "settled" : "was reported settled by the seller"}, but ${refused}, so this wallet did not ask the seller for its answer again. Nothing more was paid. To retrieve the answer, the user can allow it again with incentiv-mcp setup and you retry this request ID; buying again with a new request ID pays again.` };
      const header = paymentHeader(JSON.parse(x.accepted), x.resource ? JSON.parse(x.resource) : undefined, r.operation!, r.userOpHash as Hex, x.paymentId as Hex, x.validUntil);
      response = await this.http({ ...req, headers: { ...req.headers, "payment-signature": header }, maxBytes: MAX_RESPONSE_BYTES, timeoutMs: PAID_REQUEST_TIMEOUT_MS }).catch(() => undefined);
      if (response && httpSucceeded(response.status) && !response.incomplete) {
        r.delivered = true; r.sequence = ++journal.data.sequence; await journal.save();
        // From here the nonce is known to be used, so the payment cannot be charged again.
        return { ...x402Result(r), content_delivered: true, content: responseContent(response), next_action: "This payment had settled without its answer; the seller has now served it. Nothing more was paid." };
      }
    }
    // The lane is used, but until a receipt is verified the settlement is only what the seller reported.
    const where = r.status === "confirmed" ? `settled${r.transactionHash ? ` in ${r.transactionHash}` : ""}` : "was reported settled by the seller and its nonce is used; get_agent_operation confirms it on chain";
    const answer = r.delivered ? "its answer was handed back when it was paid, but this wallet cannot tell whether it reached you" : "its answer was lost";
    const again = replayable(req) ? "the seller did not serve it again" : "this wallet does not resend a paid POST without an Idempotency-Key header, because the seller could run it a second time";
    return { ...x402Result(r), content_delivered: false, ...(response ? { http_status: response.status } : {}), next_action: `This payment ${where}, and ${answer}; ${again}. Nothing more was paid. Buying again with a new request ID pays again; if the answer was lost, ask the seller to honour this payment instead.` };
  }

  /** The seller's deadline passed: an unsent payment expires; one the seller may hold stays reserved until resolved. */
  private async pastDeadlineX402(journal: Journal, r: OperationRecord) {
    if (r.status === "signed") {
      const expired = await this.reconcileSignedX402(journal, r);
      if (expired) return { ...x402Result(r), next_action: "The payment expired before it was sent, so nothing was paid. Use a new request ID." };
      // It never left this computer, so it will expire unpaid; only the lane read that would release it failed.
      if (expired === undefined) throw new WalletError("rpc_unavailable", "Could not read this payment's nonce lane from RPC. It was never sent and its deadline has passed, so it expires unpaid; retry with the same request ID when RPC is available to release its reservation. Do not cancel it.");
    }
    return { ...x402Result(r), next_action: X402_UNKNOWN_ACTION(r.requestId) };
  }
  /**
   * Rechecks a signed payment whose delivery was never recorded. A spent lane needs receipt reconciliation
   * immediately. An unused lane can expire only after the seller's deadline. Returns whether the payment expired,
   * or undefined when the lane could not be read.
   */
  private async reconcileSignedX402(journal: Journal, r: OperationRecord, state?: () => Promise<ChainState>): Promise<boolean | undefined> {
    const wallet = journal.session.envelope;
    const lane = await (state ? state().then(async s => ({ ...s, nonce: await this.chain.laneNonce(wallet, BigInt(r.nonce!) >> 64n, s.block) })) : this.chain.stateFor(wallet, r)).catch(() => undefined);
    if (!lane) return undefined;
    if (lane.nonce !== BigInt(r.nonce!)) {
      r.lastError = "submission_unknown";
      await journal.transition(r, "submission_unknown");
      return false;
    }
    if (r.deadline === undefined || r.deadline > Math.floor(Date.now() / 1000)) return false;
    r.lastError = "x402_payment_expired";
    await journal.transition(r, "expired");
    return true;
  }
  /** Sends the signed payment with the request, and records what the seller answered. */
  private async deliverX402(s: WalletSession, journal: Journal, r: OperationRecord, req: X402Request, limits: Limits, freshlySimulated = false) {
    const x = r.intent.x402!;
    if (x.validUntil <= Math.floor(Date.now() / 1000)) return this.pastDeadlineX402(journal, r);
    // Every send is checked against current policy: a first send is a fresh spend, and after an uncertain attempt
    // (say the process stopped before the request started) the seller may still never have received it.
    const before = r.status, first = before === "signed";
    const consequence = first ? "it was never sent and expires unpaid" : `it was not sent again. The seller may already hold it, so it stays reserved; ${X402_UNKNOWN_ACTION(r.requestId)}`;
    const snapshot = await this.recheckX402(s, journal, r, limits, consequence, freshlySimulated);
    await this.canSubmit(s, r);
    assertPolicyLive(limits, consequence);
    r.attempts++;
    await journal.transition(r, "submitting"); // From here the seller may hold the signed payment.
    // The chain, wallet enablement, policy expiry and deadline can change during the write. A refusal here
    // restores the previous delivery state because this attempt never left the wallet.
    const unsent = async () => { r.attempts--; await journal.transition(r, before); };
    try {
      await this.chain.assertCanonicalSnapshot(snapshot).catch(rethrowSnapshotError);
      await this.canSubmit(s, r);
      assertPolicyLive(limits, consequence);
    }
    catch (error) { await unsent(); throw error; }
    if (x.validUntil <= Math.floor(Date.now() / 1000)) { await unsent(); return this.pastDeadlineX402(journal, r); }
    const header = paymentHeader(JSON.parse(x.accepted), x.resource ? JSON.parse(x.resource) : undefined, r.operation!, r.userOpHash as Hex, x.paymentId as Hex, x.validUntil);
    let response;
    try { response = await this.http({ ...req, headers: { ...req.headers, "payment-signature": header }, maxBytes: MAX_RESPONSE_BYTES, timeoutMs: PAID_REQUEST_TIMEOUT_MS }); }
    catch (error) {
      // Some failures prove no request was written: the name did not resolve (or resolved somewhere private), the
      // connection was refused or unreachable, or TLS verification failed before any data was sent.
      if (neverSent(error)) {
        await unsent();
        throw new WalletError("x402_request_failed", `The seller could not be reached, so this attempt sent nothing: ${error instanceof Error ? error.message.slice(0, 200) : "unknown error"}. ${first ? "Retry with the same request ID while the deadline is open; an unsent payment expires unpaid." : X402_UNKNOWN_ACTION(r.requestId)}`);
      }
      r.lastError = "submission_unknown"; await journal.transition(r, "submission_unknown");
      return { ...x402Result(r), next_action: `The seller did not answer, so the payment may or may not settle. ${replayable(req) ? "Retry pay_x402_resource with the same request ID while the deadline is open; " : ""}${X402_UNKNOWN_ACTION(r.requestId)}` };
    }
    const settled = sellerSettlement(settlement(response), s.envelope.account);
    const served = httpSucceeded(response.status) && !response.incomplete;
    // The seller's report of a successful settlement is kept whatever the HTTP status, since an upfront payment
    // can settle before a handler fails. Reconciliation verifies it on chain either way.
    const paid = settled?.success === true && response.status !== 402;
    if (settled?.success === true && settled.transaction) r.transactionHash = settled.transaction;
    if (served) r.delivered = true;
    if (paid) { delete r.lastError; await journal.transition(r, "submitted"); }
    else {
      r.lastError = response.status === 402 ? "x402_payment_refused" : "x402_settlement_unconfirmed";
      await journal.transition(r, "submission_unknown");
    }
    let sellerError: string | undefined;
    if (response.status === 402) try { sellerError = String(parsePaymentRequired(response).error ?? "").slice(0, 300) || undefined; } catch { /* no readable reason */ }
    const recover = replayable(req) ? "Retry with the same request ID to ask the seller for it again; nothing more is paid." : "This wallet does not resend a paid POST without an Idempotency-Key header; ask the seller for the answer.";
    return {
      ...x402Result(r), settlement: settled,
      ...(sellerError ? { seller_error: sellerError } : {}),
      // Content the seller served is returned even when settlement is unconfirmed: it is already here.
      // The seller's report is not a receipt: settlement stays pending until get_agent_operation shows confirmed.
      seller_reported_settlement: paid, settlement_confirmed: false,
      ...(served ? { content: responseContent(response) } : { http_status: response.status }),
      ...(response.incomplete ? { response_incomplete: true } : {}),
      next_action: paid && served ? "The seller reported settling the payment; it is pending until get_agent_operation shows it confirmed on chain. Check it before buying again."
        : paid ? `The seller reported settling the payment but ${response.incomplete ? "the response ended before its answer was complete" : `answered HTTP ${response.status} without its answer`}. ${recover} Settlement is pending until get_agent_operation shows it confirmed on chain.`
        : response.status === 402 ? `The seller refused the payment. ${X402_UNKNOWN_ACTION(r.requestId)}`
        : served ? `The seller served its answer without confirming settlement. ${X402_UNKNOWN_ACTION(r.requestId)}`
        : `The seller answered without confirming settlement. ${X402_UNKNOWN_ACTION(r.requestId)}`,
    };
  }
  private balanceTokens(limits: Limits): string[] {
    return ["native", ...Object.keys(limits.tokens), ...Object.values(this.ctx.config.manifest.canonicalTokens).map(p => p.address), this.ctx.config.manifest.contracts.wcent.address];
  }
  async get() {
    return this.store.session(async s => {
      const journal = await Journal.open(s, !s.envelope.policy.configured);
      await this.reconcile(journal);
      const state = await this.chain.state(s.envelope).catch((error: unknown) => { throw rpcOutage(error); }), policy = s.envelope.policy;
      const balances = await this.chain.balances(s.envelope, policy.configured ? this.balanceTokens(policy.limits) : ["native"]).catch((error: unknown) => { throw rpcOutage(error); });
      const reserved: Spend = {};
      for (const r of journal.data.records.filter(r => ownsNonce(r.status))) for (const [token, amount] of Object.entries(r.reservation)) addSpend(reserved, token, BigInt(amount));
      const spendable = Object.fromEntries(Object.entries(balances).map(([token, amount]) => [token, (BigInt(amount) > BigInt(reserved[token] ?? "0") ? BigInt(amount) - BigInt(reserved[token] ?? "0") : 0n).toString()]));
      const disabled = await s.disabled() || !policy.enabled;
      const gasDeposit = await this.chain.gasDeposit(s.envelope);
      // release_approved is retained as a legacy alias for the local signing gate.
      // It never attests to public release review or npm publication.
      return { ...publicWallet(s.envelope), reason: !policy.configured ? "policy_not_configured" : disabled ? "wallet_disabled" : "operation_required_for_gas_estimate", deployed: state.deployed, balances, entrypoint_gas_deposit_wei: gasDeposit, pending_reservations: reserved, spendable_before_new_gas: spendable, gas_options: policy.configured ? Object.keys(policy.limits.tokens) : [], estimated_max_gas_payment: null, pending_operations: journal.data.records.filter(r => !terminal(r.status)).map(operationResult), candidate_signing_enabled: this.signingEnabled, release_approved: this.signingEnabled, next_action: !policy.configured ? "Run incentiv-mcp setup in your own terminal" : disabled ? "Run incentiv-mcp setup to review permissions, back up and re-enable" : "Provide a transfer or swap intent to check exact transfer-plus-gas readiness" };
    });
  }
  async operation(id: string) {
    return this.store.session(async s => {
      const journal = await Journal.open(s); await this.reconcile(journal);
      const key = id.toLowerCase();
      const r = journal.data.records.find(r => r.requestId === key || r.userOpHash === key ||
        r.replacement?.userOpHash === key || r.priorReplacement?.userOpHash === key);
      const archived = r ? undefined : journal.data.archived?.find(a => a.requestId === key || a.userOpHash === key ||
        a.replacementUserOpHash === key || a.priorReplacementUserOpHash === key);
      if (archived) return archivedResult(archived);
      if (!r) throw new WalletError("operation_not_found", "No journaled operation matches this ID or hash");
      // An x402 payment is shown as pay_x402_resource shows it, in USDC rather than atomic units.
      return operationResult(r);
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
        const balances = await this.spendingBalances(journal, this.balanceTokens(limits), state), used = journal.used();
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
      const journal = await Journal.open(s); await this.reconcile(journal, true);
      const r = journal.data.records.find(r => r.requestId === id);
      // Reconciliation archives a payment that ended without reaching a seller, possibly in this same pass.
      const archived = r ? undefined : journal.data.archived?.find(a => a.requestId === id);
      if (archived) return archivedResult(archived);
      if (!r) throw new WalletError("operation_not_found", "Unknown request ID");
      if (r.status === "superseding") await this.submitReplacement(s, journal, r);
      // Only the seller submits an x402 payment; this wallet never relays it, and cancels it only by replacement.
      else if (r.intent.kind !== "x402_payment" && (r.status === "signed" || r.status === "submission_unknown")) await this.submit(s, journal, r);
      return result(r);
    });
  }

  /**
   * The saved bindings of unpaid POSTs made at or before `cutoff`, for the user to review before clearing them.
   * A cleared request ID is free again, so a retry under it would send its POST once more.
   */
  async x402Bindings(cutoff: number) {
    return this.store.session(async s => {
      const journal = await Journal.open(s); await this.reconcile(journal);
      const probes = journal.data.probes ?? [], clearable = probes.filter(p => p.at <= cutoff);
      return { wallet: publicWallet(s.envelope), cutoff: new Date(cutoff).toISOString(), total: probes.length, limit: MAX_PROBES, clearable: clearable.length,
        by_outcome: Object.fromEntries(["sending", "not_required", "payment_required"].map(o => [o, clearable.filter(p => p.outcome === o).length])),
        request_ids: clearable.map(p => p.requestId) };
    });
  }
  /** Clears exactly the reviewed bindings, with the administration passphrase. */
  async clearX402Bindings(cutoff: number, passphrase: Buffer, reviewedDigest: Hex) {
    return this.store.session(async s => {
      await authorize(s.envelope.policy, passphrase);
      const journal = await Journal.open(s); await this.reconcile(journal);
      const ids = (journal.data.probes ?? []).filter(p => p.at <= cutoff).map(p => p.requestId);
      if (digest(ids) !== reviewedDigest) throw new WalletError("approval_required", "Saved POST bindings changed; review them again");
      const cleared = new Set(ids);
      journal.data.probes = (journal.data.probes ?? []).filter(p => !cleared.has(p.requestId));
      journal.data.sequence++; await journal.save();
      return { cleared: ids.length, remaining: journal.data.probes.length };
    });
  }

  /** Archived x402 payments ended at or before `cutoff`, for the user to review before clearing them. */
  async x402Archive(cutoff: number) {
    return this.store.session(async s => {
      const journal = await Journal.open(s); await this.reconcile(journal);
      const archive = journal.data.archived ?? [], clearable = archive.filter(a => a.at <= cutoff);
      return { wallet: publicWallet(s.envelope), cutoff: new Date(cutoff).toISOString(), total: archive.length, journal_bytes: journal.bytes, clearable: clearable.length, request_ids: clearable.map(a => a.requestId) };
    });
  }
  /**
   * Clears the reviewed archive entries that are still archived and older than the cutoff, with the administration
   * passphrase. Their request IDs could then pay again. A payment archived after the review is left for the next one.
   */
  async clearX402Archive(cutoff: number, passphrase: Buffer, reviewed: readonly string[]) {
    return this.store.session(async s => {
      await authorize(s.envelope.policy, passphrase);
      const journal = await Journal.open(s); await this.reconcile(journal);
      const shown = new Set(reviewed);
      const ids = (journal.data.archived ?? []).filter(a => a.at <= cutoff && shown.has(a.requestId)).map(a => a.requestId);
      const cleared = new Set(ids);
      journal.data.archived = (journal.data.archived ?? []).filter(a => !cleared.has(a.requestId));
      journal.data.sequence++; await journal.save();
      return { cleared: ids.length, remaining: journal.data.archived.length, journal_bytes: journal.bytes };
    });
  }

  async reviewReplacement(id: string, nativeGas = false) {
    return this.store.session(async s => {
      await this.enabled(s);
      const journal = await Journal.open(s); await this.reconcile(journal);
      const r = journal.data.records.find(r => r.requestId === id);
      // A signed token-paid replacement can become unsendable: the bundler refuses the same bytes once the paymaster's
      // terms move. It may still land, so it is kept, but a native replacement may be reviewed over it, once.
      const overToken = !!r?.replacement?.signed && r.replacement.gasToken !== undefined && !r.priorReplacement;
      const archived = r ? undefined : journal.data.archived?.find(a => a.requestId === id);
      if (archived) throw new WalletError("operation_pending", `Request ${id} already ended as ${archived.status} and is archived; it holds no nonce, so there is nothing to replace`);
      if (!r || !ownsNonce(r.status) || (r.replacement?.signed && !(overToken && nativeGas))) throw new WalletError("operation_pending", `Replacement requires an unresolved original operation without a signed replacement${overToken ? `; a signed replacement that pays gas in a token can be replaced once more with wallet operation resolve ${id} --replace --native-gas` : ""}`);
      if (r.priorReplacement && !nativeGas) throw new WalletError("operation_pending", `Request ${id} already has a signed token-paid replacement, so only a native one can follow it: run wallet operation resolve ${id} --replace --native-gas`);
      // For an x402 payment this cancels it: any operation on its nonce lane makes the payment unusable (SPEC 6).
      const state = await this.chain.stateFor(s.envelope, r).catch((error: unknown) => { throw rpcOutage(error); });
      // Native gas clears the nonce when the token balance or paymaster cannot.
      const gasToken = nativeGas ? "native" : r.intent.gasToken;
      const built = await this.replacementStep(r.requestId, gasToken, () => this.chain.buildReplacement(s.envelope, r, state, gasToken));
      const wire = userOpToJson(built.op);
      const validated = validateOperation(this.ctx.config, s.envelope, this.replacementIntent(s, gasToken), wire, { nonce: BigInt(r.nonce!), deployed: state.deployed, hash: built.userOpHash });
      await this.replacementStep(r.requestId, gasToken, () => this.chain.simulate(validated));
      if (overToken) r.priorReplacement = r.replacement;
      r.replacement = { operation: wire, userOpHash: validated.hash, maxGasCost: validated.gasCost.toString(), ...(gasToken !== "native" ? { gasToken, gasCharge: validated.gasCharge.toString() } : {}), signed: false, expiresAt: Date.now() + 300_000 };
      r.sequence = ++journal.data.sequence; await journal.save();
      return { wallet: publicWallet(s.envelope), records: [structuredClone(r)] };
    });
  }
  /** A stuck nonce is urgent: say what to do next rather than suggesting storage damage. */
  private async replacementStep<T>(id: string, gasToken: string, step: () => Promise<T> | T): Promise<T> {
    try { return await step(); } catch (error) {
      // The paymaster's refusal suggests a new request ID, but this request still holds the nonce, so only native gas can replace it.
      if (error instanceof WalletError && error.code === "gas_token_unavailable" && gasToken !== "native") throw new WalletError(error.code, `${error.detail.replace(/\s*Use a new request ID\b.*$/s, "")} Request ${id} still holds the account nonce, so a new request ID would be refused. To pay this replacement's gas in ${this.ctx.config.identity.nativeSymbol}, run wallet operation resolve ${id} --replace --native-gas in your local terminal.`);
      // Only gas payment problems can be cleared by paying in native gas; other errors keep their own guidance.
      if (error instanceof WalletError) throw GAS_FIXABLE_ERRORS.includes(error.code) ? new WalletError(error.code, `${error.message.slice(error.code.length + 2)}.${nativeGasHint(this.ctx.config, gasToken)}`) : error;
      if (error instanceof NetworkError) throw error;
      // An outage says nothing about the gas token, so paying in native gas would not help.
      if (rpcOutage(error) !== error) throw new WalletError("rpc_unavailable", "Could not reach the RPC or bundler to prepare this replacement; retry");
      throw new WalletError("validation_failed", `Could not prepare this replacement; retry.${nativeGasHint(this.ctx.config, gasToken)}`);
    }
  }
  private replacementIntent(s: WalletSession, gasToken = "native"): Intent {
    return { intentSchemaVersion: 1, kind: "transfer", token: "native", amount: "0", gasToken, to: s.envelope.account, slippageBps: 0, feeTier: 3000 };
  }
  async replace(id: string, passphrase: Buffer, reviewedDigest: Hex) {
    return this.store.session(async s => {
      await authorize(s.envelope.policy, passphrase); await this.canSubmit(s);
      const journal = await Journal.open(s); await this.reconcile(journal, true);
      const r = journal.data.records.find(r => r.requestId === id);
      if (!r || !ownsNonce(r.status) || !r.replacement || r.replacement.signed || r.replacement.expiresAt <= Date.now() || digest(r) !== reviewedDigest) throw new WalletError("approval_required", "Replacement changed or expired; review it again");
      const state = await this.chain.stateFor(s.envelope, r).catch((error: unknown) => { throw rpcOutage(error); });
      if (state.nonce !== BigInt(r.nonce!)) throw new WalletError("operation_pending", "Original nonce has already moved; reconcile before replacing");
      const replacement = r.replacement;
      const validated = validateOperation(this.ctx.config, s.envelope, this.replacementIntent(s, replacement.gasToken ?? "native"), replacement.operation, { nonce: state.nonce, deployed: state.deployed, hash: replacement.userOpHash });
      if (validated.gasCost.toString() !== replacement.maxGasCost) throw new WalletError("validation_failed", "Replacement gas ceiling changed");
      const gasToken = replacement.gasToken ?? "native";
      if (gasToken !== "native" && validated.gasCharge.toString() !== replacement.gasCharge) throw new WalletError("validation_failed", "Replacement token gas payment changed");
      await this.replacementStep(r.requestId, gasToken, () => this.chain.simulate(validated));
      await this.checkReplacementBalance(journal, r, gasToken, validated.gasCharge.toString(), state).catch((error: unknown) => { throw rpcOutage(error); });
      await this.canSubmit(s);
      if (replacement.expiresAt <= Date.now()) throw new WalletError("approval_required", "Replacement review expired before signing");
      replacement.operation.signature = await this.signRaw(s, validated.hash);
      replacement.signed = true; replacement.fromBlock = state.block.toString();
      // Keep the original reservation, and an earlier replacement's, as well: any signed operation might win.
      addSpend(r.reservation, gasToken, validated.gasCharge);
      if (r.status === "superseding") { r.sequence = ++journal.data.sequence; await journal.save(); }
      else await journal.transition(r, "superseding");
      await this.submitReplacement(s, journal, r);
      return result(r);
    });
  }
  private async checkReplacementBalance(journal: Journal, r: OperationRecord, gasToken: string, gasCharge: string, state?: ChainState) {
    const balances = await this.spendingBalances(journal, [gasToken], state);
    // The original and replacements share one nonce. Other lanes may still settle independently.
    if (!covers(balances, journal, { [gasToken]: gasCharge }, r)) throw new WalletError("policy_denied", `Balance cannot cover the reviewed replacement gas payment beside other pending operations.${nativeGasHint(this.ctx.config, gasToken)}`);
  }
  private async submitReplacement(s: WalletSession, journal: Journal, r: OperationRecord) {
    await this.canSubmit(s);
    // The latest signed replacement; while a native one reviewed over a token-paid one is unsigned, that earlier one.
    const signed = r.replacement?.signed ? r.replacement : r.priorReplacement;
    if (!signed || r.status !== "superseding") throw new WalletError("wallet_recovery_required", "Missing signed replacement");
    r.attempts++; r.sequence = ++journal.data.sequence; await journal.save();
    let refusal: { error: unknown } | undefined, landed = false;
    try {
      const hash = await this.chain.relay(signed.operation, async () => {
        try {
          const state = await this.chain.stateFor(s.envelope, r).catch(rethrowSnapshotError);
          // A used nonce means the original or a replacement already landed and paid its gas, so the balance
          // no longer shows it. Relaying again does nothing; reconciliation finds which one won.
          if (state.nonce > BigInt(r.nonce!)) { landed = true; throw new Error("Nonce already used"); }
          await this.checkReplacementBalance(journal, r, signed.gasToken ?? "native", signed.gasCharge ?? signed.maxGasCost, state);
          await this.canSubmit(s);
        } catch (error) {
          if (!landed) refusal = { error: rpcOutage(error) };
          throw error;
        }
      });
      if (hash !== signed.userOpHash) throw new Error();
      delete r.lastError;
    } catch {
      if (refusal || landed) r.attempts--;
      else r.lastError = "submission_unknown";
    }
    r.sequence = ++journal.data.sequence; await journal.save();
    if (refusal) throw refusal.error;
  }
}
const httpSucceeded = (status: number) => status >= 200 && status < 300;

/** An unpaid error body is seller-written text the tool screens. A non-text body can't be screened, so it is only described. */
function errorContent(response: HttpResponse) {
  const { base64: _binary, ...content } = responseContent(response) as ReturnType<typeof responseContent> & { base64?: string };
  return content;
}
function unpaidHttpFailure(response: HttpResponse) {
  return {
    status: "request_failed",
    http_status: response.status,
    content: errorContent(response),
    next_action: response.incomplete
      ? "The resource response was interrupted before a payment was sent. Check the resource before retrying."
      : `The resource returned HTTP ${response.status} before a payment was sent. Check the resource response before retrying.`,
  } as const;
}

/**
 * A payment or cancellation reopened while an RPC lagged, found again in the same block, is the same settlement: its
 * spend keeps its original time instead of counting against the daily limit for another day.
 */
const sameSettlement = (r: OperationRecord, blockHash: Hex | undefined) => r.consumedAt !== undefined && blockHash !== undefined && blockHash === r.settledBlockHash;
/** A receipt search's saved progress, compared to see whether a pass moved it. */
const searchProgress = (x: Pick<OperationRecord, "searchedBlock" | "discoveredBlock" | "retryLogs">) => JSON.stringify([x.searchedBlock, x.discoveredBlock, x.retryLogs]);
/** A failed read, or configured RPCs that disagree (one lagging behind, say): neither says anything about the wallet. */
const rpcFault = (error: unknown) => !(error instanceof WalletError) || error instanceof RpcDisagreementError;
/**
 * Any failed read in the settlement recheck, including a lagging node's missing block or header or RPCs that
 * disagree, says nothing about the wallet: it becomes rpc_unavailable rather than escaping as
 * wallet_recovery_required or validation_failed.
 */
function rethrowX402RecheckError(error: unknown): never {
  if (!rpcFault(error)) throw error;
  throw new WalletError("rpc_unavailable", "Could not recheck recent x402 settlements; retry when RPC is available");
}

const MAX_LINK_ATTEMPTS = 8;
/** A failed read in the checks before a signed payment is sent or resent: this call sends nothing, and the record keeps its request ID. */
function rethrowSendCheckError(error: unknown): never {
  if (!rpcFault(error)) throw error;
  throw new WalletError("rpc_unavailable", "Could not read chain state from RPC before sending this payment, so this call did not send it; retry with the same request ID");
}
/** A chain read for an ordinary spend that failed, or whose block was replaced; retrying reads a new snapshot. */
function rethrowSnapshotError(error: unknown): never {
  if (!rpcFault(error)) throw error;
  throw new WalletError("rpc_unavailable", "Chain state changed or RPC is unavailable during the wallet check; retry this request");
}
/** Runs tasks with at most `limit` in flight. On a failure it starts no more, waits for those running, then throws. */
async function pooled(tasks: (() => Promise<void>)[], limit: number): Promise<void> {
  let next = 0, failure: { error: unknown } | undefined;
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, async () => {
    while (!failure && next < tasks.length) {
      const task = tasks[next++];
      try { await task(); } catch (error) { failure ??= { error }; }
    }
  }));
  if (failure) throw failure.error;
}
/** An RPC or bundler outage, or configured RPCs that disagree, says nothing about a request, so it becomes a retryable rpc_unavailable; anything else is returned as is. */
const rpcOutage = (error: unknown) => error instanceof RpcDisagreementError || (!(error instanceof WalletError) && (isTransportFailure(error) || error instanceof BundlerUnavailableError))
  ? new WalletError("rpc_unavailable", "Could not read chain state from RPC; retry this request") : error;
/** Refusals that say nothing about the request itself, so an unsigned request returns to approval_required and keeps its ID. */
// Renewing the local policy clears registry_approval_outlasts_policy, so the request keeps its ID for that too.
// A full parent stays retryable as for signed bytes: the registry's limit can change.
const TEMPORARY_ERRORS = ["registry_rpc_unavailable", "rpc_unavailable", "registry_factory_not_allowed", "registry_parent_not_eligible", "registry_approval_outlasts_policy", "registry_limit_reached"];
/** Registry refusals that the same signed bytes can never get past. */
const UNSENDABLE_REGISTRY_ERRORS = ["registry_approval_stale", "registry_approval_expired", "registry_approval_invalid", "registry_link_changed", "registry_unlink_unsupported",
  // Connections are permanent, so an agent that is already linked, or an account role that forbids the link, does not change.
  "registry_already_linked", "registry_ineligible"];
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

/** Whether a paid request may be sent again: a GET, or a POST the caller marked with an Idempotency-Key for the seller. */
const replayable = (req: X402Request) => req.method === "GET" || !!req.headers["idempotency-key"]?.trim();
/** What a retry can do for a paid answer: a POST without an Idempotency-Key is never sent again, even once paid. */
const answerAdvice = (req: X402Request) => replayable(req) ? "retry this request ID for the answer" : "its answer can't be requested again, since this wallet does not resend a paid POST without an Idempotency-Key";

/**
 * How long a paid request waits for its answer: longer than the stock facilitator's 60-second settle window, so a
 * slow settlement still returns the answer instead of finishing after the wallet stopped waiting.
 */
const PAID_REQUEST_TIMEOUT_MS = 90_000;
/** An unpaid request runs under the wallet lock in pay_x402_resource, so it gets the same short bound as get_x402_payment_requirements. */
const UNPAID_REQUEST_TIMEOUT_MS = 30_000;
/**
 * Reorg check window for existing settlements that predate recording their receipt block.
 */
const X402_RECONFIRM_MS = 60 * 60_000;
/** Maximum simultaneous settlement reads per configured RPC. */
export const X402_SETTLEMENT_CONCURRENCY = 4;
/** Terminal x402 payments older than this are archived; the daily limit only looks back one day. */
const COMPACT_AFTER_MS = 2 * 86_400_000;
/** New x402 payments pause above this journal size, leaving room below the 16 MiB limit for everything else. */
const X402_JOURNAL_BYTES = 12 * 1024 * 1024;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
/** Payments that never reached a seller: nothing can send them again or ask for their answer, so they are archived at once. */
const UNSENT_TERMINAL = ["failed", "expired", "cancelled"];
/** Outcomes a receipt settled: an earlier delivery error no longer describes them. */
const SETTLED_STATUSES = ["confirmed", "reverted", "superseded"];
/** An archived x402 payment as get_agent_operation and wallet operation resolve show it: it has ended, so nothing remains to do. */
function archivedResult(archived: z.infer<typeof archivedSchema>) {
  return {
    request_id: archived.requestId, intent: { kind: "x402_payment" }, status: archived.status,
    user_op_hash: archived.userOpHash, replacement_user_op_hash: archived.replacementUserOpHash,
    prior_replacement_user_op_hash: archived.priorReplacementUserOpHash, transaction_hash: archived.transactionHash,
    last_error: archivedError(archived), archived: true,
  };
}
const archivedError = (archived: { status: string; lastError?: string }) => SETTLED_STATUSES.includes(archived.status) ? undefined : archived.lastError;
/** A refused unpaid request needs its binding only while a retry with its request ID is likely. */
const REFUSED_PROBE_MS = 86_400_000;
/** Bindings of unpaid POSTs that the resource may have acted on are kept for good, up to this many (about 2 MB). */
const MAX_PROBES = 10_000;
/**
 * Keeps x402 volume from filling the journal. A terminal payment is replaced by a small archive entry that keeps
 * what binds its request ID (the request digest), its outcome and its hashes: at once if it never reached a seller,
 * otherwise after two days, since a settled one may be asked for its answer again and its spend counts against the
 * daily limit for a day. Archive entries are kept, so a request ID never pays twice, until the user clears old ones
 * (wallet x402 clear-archive). A refused unpaid request's binding is dropped after a day: the resource did not act on it.
 */
async function compactX402(journal: Journal, now = Date.now()) {
  let changed = false;
  const probes = journal.data.probes?.filter(p => p.outcome !== "payment_required" || p.at > now - REFUSED_PROBE_MS);
  if (probes && probes.length !== journal.data.probes!.length) { journal.data.probes = probes; changed = true; }
  const archive = [...journal.data.archived ?? []];
  const records = journal.data.records.filter(r => {
    if (r.intent.kind !== "x402_payment" || !terminal(r.status)) return true;
    if (!UNSENT_TERMINAL.includes(r.status)) {
      if (r.updatedAt > now - COMPACT_AFTER_MS) return true;
      if (r.settledBlock !== undefined && !r.settlementFinal) return true;
    }
    // A settled outcome supersedes any earlier delivery error, as the live record shows it.
    const lastError = archivedError(r);
    archive.push({
      requestId: r.requestId, request: r.intent.x402!.request, status: r.status, at: r.updatedAt,
      ...(lastError ? { lastError: lastError.slice(0, 64) } : {}),
      ...(r.userOpHash ? { userOpHash: r.userOpHash } : {}),
      ...(r.replacement?.signed ? { replacementUserOpHash: r.replacement.userOpHash } : {}),
      ...(r.priorReplacement ? { priorReplacementUserOpHash: r.priorReplacement.userOpHash } : {}),
      ...(r.transactionHash ? { transactionHash: r.transactionHash } : {}),
    });
    return false;
  });
  if (records.length !== journal.data.records.length) changed = true;
  if (changed) { journal.data.records = records; journal.data.archived = archive; journal.data.sequence++; await journal.save(); }
}

/**
 * Whether the balance covers `spend` once every other pending operation's reservation is set aside. x402 payments
 * hold their own nonce lanes, so several can be pending beside each other and beside one main-nonce operation.
 * A payment the seller settled is counted against both until its receipt confirms it, which errs on refusing.
 */
function covers(balances: Spend, journal: Journal, spend: Spend, except?: OperationRecord): boolean {
  const reserved: Spend = {};
  for (const o of journal.data.records) if (o !== except && ownsNonce(o.status)) for (const [token, amount] of Object.entries(o.reservation)) addSpend(reserved, token, BigInt(amount));
  return Object.entries(spend).every(([token, amount]) => BigInt(balances[token] ?? "0") - BigInt(reserved[token] ?? "0") >= BigInt(amount));
}

/** An undeployed account is created by the first operation that lands; another signed to create it too would then fail. */
function assertDeploysOnce(deployed: boolean, journal: Journal) {
  const pending = deployed ? undefined : journal.data.records.find(o => ownsNonce(o.status));
  if (pending) throw new WalletError("operation_pending", `This account is not deployed yet and pending request ${pending.requestId} deploys it; retry once get_agent_operation shows it settled`);
}

/** A Portal approval lasts AGENT_LINK_MIN_SECONDS, and link_agent refuses one that outlasts local policy. */
function assertOutlastsApproval(limits: Limits) {
  if (limits.expiresAt && limits.expiresAt < Date.now() + AGENT_LINK_MIN_SECONDS * 1000) throw new WalletError("policy_expired", `Local wallet policy expires within ${AGENT_LINK_MIN_SECONDS / 60} minutes, before a Portal approval would, so link_agent could not use one. Renew it with incentiv-mcp setup in your local terminal`);
}

/** Why a new request cannot start while `holder` owns the account nonce, with the step that frees it. */
function mainNoncePending(holder: OperationRecord, next: string) {
  const id = holder.requestId;
  // An unlink an earlier build recorded is never sent again, so only a same-nonce replacement frees the nonce.
  if (holder.intent.kind === "unlink_agent" && holder.status === "signed") return new WalletError("operation_pending", `Request ${id} is an unlink signed by an earlier build, which this wallet no longer sends, and it holds the account nonce. Clear it with wallet operation resolve ${id} --replace in your local terminal, then ${next}`);
  if (holder.intent.kind === "unlink_agent") return new WalletError("operation_pending", `Request ${id} is an unlink from an earlier build that holds the account nonce. Check it with get_agent_operation; if it does not confirm, clear it with wallet operation resolve ${id} --replace in your local terminal, then ${next}`);
  return new WalletError("operation_pending", `Request ${id} owns the account nonce; check it with get_agent_operation until it settles, then ${next}`);
}

/**
 * The seller's settlement report with only well-formed values. A network or payer other than this payment's own is
 * dropped, so the result and its x402 MCP metadata never name another chain or account. Its free text is cut short
 * here and screened by the tool.
 */
function sellerSettlement(settled: SettleResponse | undefined, account: string) {
  if (!settled) return;
  const match = (value: unknown, pattern: RegExp) => typeof value === "string" && pattern.test(value) ? value.toLowerCase() : undefined;
  const reason = typeof settled.errorReason === "string" ? settled.errorReason.slice(0, 300) || undefined : undefined;
  const payer = match(settled.payer, /^0x[0-9a-fA-F]{40}$/);
  // A settlement on another network is not this payment's, so none of it is reported as settled.
  const elsewhere = settled.network !== undefined && settled.network !== X402_NETWORK;
  const fields = { transaction: elsewhere ? undefined : match(settled.transaction, /^0x[0-9a-fA-F]{64}$/), network: settled.network === X402_NETWORK ? X402_NETWORK : undefined, payer: payer === account.toLowerCase() ? payer : undefined, error_reason: reason };
  // A successful SettleResponse names its transaction and network. Without both the report cannot be checked or passed
  // on as one, so the payment stays unconfirmed until reconciliation finds it on chain.
  return { success: settled.success === true && !!fields.transaction && fields.network === X402_NETWORK, ...Object.fromEntries(Object.entries(fields).filter(([, value]) => value !== undefined)) } as { success: boolean; transaction?: string; network?: string; payer?: string; error_reason?: string };
}

/**
 * Transport failures that can only happen before any request bytes are written: name resolution, a refused
 * connection and TLS verification. ENETUNREACH and EHOSTUNREACH are not here: an established connection can end
 * with them after the request went out, so only the transport's own connection state (sentNothing) counts them.
 */
const NEVER_SENT_CODES = ["ENOTFOUND", "EAI_AGAIN", "ECONNREFUSED", "ERR_TLS_CERT_ALTNAME_INVALID", "CERT_HAS_EXPIRED", "DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY"];
function neverSent(error: unknown) {
  return error instanceof WalletError || sentNothing(error) || NEVER_SENT_CODES.includes((error as { code?: string } | undefined)?.code ?? "");
}

/** Policy expiry is checked again at the last moment before a payment is signed or first leaves this computer. */
function assertPolicyLive(limits: Limits, consequence: string) {
  if (limits.expiresAt && Date.now() >= limits.expiresAt) throw new WalletError("policy_denied", `Local wallet policy expired; ${consequence}`);
}

const X402_UNKNOWN_ACTION = (id: string) => `Its amount stays reserved until the payment settles or is cancelled. Check get_agent_operation; to cancel it, the user runs incentiv-mcp wallet operation resolve ${id} --replace in their own terminal.`;

/** An operation as the wallet tools show it: an x402 payment in USDC as pay_x402_resource shows it, anything else as recorded. */
const operationResult = (r: OperationRecord) => r.intent.kind === "x402_payment" ? x402Result(r) : result(r);

/** An x402 record for the agent: the request and payment, without the seller's raw JSON. */
function x402Result(r: OperationRecord) {
  const { accepted, resource, request, ...x402 } = r.intent.x402!;
  return { ...result(r), intent: { kind: r.intent.kind, amount: formatUnits(BigInt(r.intent.amount), USDC_DECIMALS), asset: "USDC", pay_to: r.intent.to, gas_token: r.intent.gasToken, scheme: X402_SCHEME, ...x402, maxAmount: formatUnits(BigInt(x402.maxAmount), USDC_DECIMALS) } };
}

function result(r: OperationRecord) {
  const nativeGas = r.intent.gasToken === "native" && (r.status === "confirmed" || r.status === "reverted") && r.consumed?.native !== undefined
    ? (BigInt(r.consumed.native) - (r.status === "confirmed" && r.intent.token === "native" ? BigInt(r.intent.amount) : 0n)).toString() : undefined;
  const { registryApproval, x402, ...publicIntent } = r.intent;
  // The seller's raw terms are third-party text that no tool screens here, so only the payment's own fields are shown.
  const sellerFree = x402 ? (({ accepted: _accepted, resource: _resource, ...own }) => own)(x402) : undefined;
  const intent = { ...publicIntent, ...(sellerFree ? { x402: sellerFree } : {}), ...(registryApproval ? { registryApproval: { ...registryApproval, parent_signature: "[redacted]" } } : {}) };
  const eventMissing = r.status === "confirmed" && r.lastError === "registry_event_missing";
  const registryError = eventMissing || (r.status === "reverted" && isRegistryIntent(r.intent) && r.lastError?.startsWith("registry_")) ? r.lastError : undefined;
  const interrupted = r.status === "approval_required" && TEMPORARY_ERRORS.includes(r.lastError ?? "");
  return { request_id: r.requestId, intent, registry_error: registryError, ...(eventMissing ? { next_action: "The operation succeeded on-chain but its registry event was not found. Check get_agent_registry_status before relying on this change." } : registryError ? { next_action: registryNextAction(r.intent.kind, registryError) } : interrupted ? { next_action: `${r.lastError === "registry_factory_not_allowed" ? "The Agent Registry does not currently allow this account's factory. Retry with the same request ID once it does, while the Portal approval is still valid" : r.lastError === "registry_parent_not_eligible" ? "The Agent Registry does not currently accept this Portal account as a parent. Retry with the same request ID once it does, while the Portal approval is still valid"
      : r.lastError === "registry_limit_reached" ? "This Portal account has reached its agent limit. Retry with the same request ID if the limit changes, while the Portal approval is still valid"
      : r.lastError === "registry_approval_outlasts_policy" ? "The Portal approval lasts past the local wallet policy's expiry. Once the user renews the policy with incentiv-mcp setup, retry with the same request ID while the Portal approval is still valid" : "A temporary RPC failure interrupted this request. Retry with the same request ID"}${r.reasons?.length ? "." : "; terminal approval is not needed."}` } : {}), status: r.status, user_op_hash: r.userOpHash, replacement_user_op_hash: r.replacement?.userOpHash, prior_replacement_user_op_hash: r.priorReplacement?.userOpHash, transaction_hash: r.transactionHash, actual_native_gas_cost_wei: nativeGas, reasons: r.status === "approval_required" ? r.reasons : undefined, attempts: r.attempts, last_error: ["confirmed", "reverted", "superseded"].includes(r.status) ? undefined : r.lastError };
}
