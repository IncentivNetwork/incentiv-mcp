# Agent Registry connections

The mainnet proxy is `0x1Be49e07439A4c3B1B95E1A9ba1031f477306012`, chain ID 24101. This integration supports two flows. In the Portal-submitted flow, the agent signs its own `AgentLink` consent for one parent and Portal sends `link` from the parent's account. In the agent-submitted flow, Portal signs parent consent and the local agent smart account sends `link` in an ERC-4337 v0.7 operation. No parent key enters MCP in either flow.

**Connections are permanent.** Once an agent is linked, neither MCP nor Portal offers a way to disconnect it: MCP has no unlink tool and refuses unlink requests (`registry_unlink_unsupported`), and Portal has no disconnect action. The registry contract itself still has `unlink()` and `unlinkAgent()`, so this is a product rule, not an on-chain guarantee. Because a link uses up one of the parent's agent slots for good, confirm the parent address before signing.

## Connect from Portal

This flow needs a deployed agent account.

1. Allow the parent in local policy (see below) with `incentiv-mcp setup`.
2. Call `sign_agent_link` with `parent` set to that Portal smart account. MCP checks the registry and the parent, computes the `AgentLink` digest locally and requires the registry's `agentLinkDigest` to match it at the same block, signs its bytes with the agent key (EIP-191), and checks that the agent account accepts the signature. Nothing is submitted.
3. Give the returned Portal URL to the user. It carries `parent`, `agent_nonce`, `agent_deadline` and `agent_signature`. The user trusts the agent in Portal, then confirms the connection, which Portal sends from their account with its fee.
4. Check `get_agent_registry_status`. Do not call `link_agent` for this request.

The consent lasts 24 hours, never past the local policy's expiry, and ends earlier if this agent's registry nonce changes. A policy that expires within 15 minutes signs nothing. The consent names one parent, and the registry accepts it only in a `link` sent by that parent or signed by it, so the URL gives nobody else a way to link this agent. A parent missing from local policy, an expired policy or a disabled wallet signs nothing.

A signed consent cannot be withdrawn from MCP. Removing the parent from policy, disabling the wallet or renewing the policy stops new signatures but leaves an issued URL usable until its `agent_deadline`. Treat the URL like an approval and share it only with that parent's owner. A connection that goes through cannot be undone.

Any `link` changes this agent's registry nonce and voids its outstanding consents. So `sign_agent_link` refuses with `operation_pending` while a `link_agent` request (or an `unlink_agent` request recorded by an earlier build) may still land, and names the request. A request that is signed but was never sent is cleared by retrying it with the same `request_id`, or with `wallet operation resolve <request_id> --replace` once its deadline has passed. A request that has not been sent yet, such as one awaiting local approval, does not block signing, but the result names it in `warning`. An expired local policy is refused before any registry read.

For an agent that is not deployed yet, `sign_agent_link` signs nothing and returns `registry_agent_not_deployed`, because the registry checks the agent's signature through its deployed account. Use `prepare_agent_link` and the flow below instead.

## Connect with a Portal approval

1. Run setup and fund your agent account for gas (native CENT, or an approved token through the paymaster).
2. Call `prepare_agent_link`. Open the returned first-party Portal `/agents` URL. Never send a parent signature through a URL.
3. Check both full smart-account addresses. Portal reads the digest itself and signs its bytes using the EOA or passkey wrapper. Approvals last 15 minutes. This wallet refuses an approval that lasts more than 24 hours or past the local policy's expiry, since a signed link can land until the approval's deadline.
4. Copy the approval JSON into `link_agent` with a new `request_id` UUID, optional `gas_token` and `wait_for_confirmation`. This still requires authenticated local policy.
5. Reuse the same UUID only for identical retries. `get_agent_operation` reconciles the request; `get_agent_registry_status` reads the current relationship. Historical completion and the current relationship can differ if the link was removed outside MCP and Portal.

The agent can be undeployed: factory deployment occurs before its first `link` executes. The parent must already be deployed. The local wallet checks account derivation, ownership and the allowed factory. A factory the registry does not allow is refused with `registry_factory_not_allowed`, for a deployed or an undeployed agent. The allowlist can change, so this request ID stays usable: an unsigned request waits in `approval_required` and a signed one keeps its bytes, and either can be retried later while its Portal approval is valid. A parent the registry does not currently accept is refused with `registry_parent_not_eligible` and stays retryable the same way. Both sides must satisfy the registry roles and current limit.

## Local permissions

Setup can authorize selected Portal parent smart-account addresses. The same parent list decides which parents the agent may sign consent for. The optional authenticated policy field is:

```json
"agentRegistry": {
  "parents": ["0xYOUR_PORTAL_SMART_ACCOUNT"],
  "allowUnlink": false
}
```

`allowUnlink` stays in the format so stored policies keep loading, but it no longer permits anything: setup always writes `false`, and an unlink is refused even where an older policy says `true`. The registry's `link(address,address,uint256,bytes,uint256,bytes)` selector must also appear under its address in `targets`; setup adds it. Existing policies do not grant it. An out-of-policy request can use the existing exact-operation `wallet approve <request-id>` workflow in your terminal. Gas budgets, exposure limits, simulation, wallet disable and durable submission checks still apply. Registry calls transfer no business funds and reserve gas only. Never add arbitrary-call or arbitrary-digest signing permissions.

## Existing wallets

After updating, run:

```sh
incentiv-mcp wallet capabilities approve
incentiv-mcp setup
```

Transfers, swaps, reconciliation, backups and pending-operation commands keep working until you do; only the registry tools report `capability_manifest_unapproved`. Saving a policy or restoring a backup never approves the registry. The command derives the previous manifest by removing the registry from the active configuration. With a custom network that changes anything else, pass `--previous /absolute/path/previous-config.json`.

Approval preserves wallet identity, addresses, keys and journal history. It is one-way: once a wallet approves the registry, releases before 0.4.0 cannot open it and report `wallet_recovery_required: Invalid or incomplete wallet envelope`. Nothing is damaged; reinstall 0.4.0 or later. A wallet that 0.4.0 has only opened, without approving, still works with older releases. It refuses unresolved signed operations, which you can check and resolve with the usual commands first; a registry request signed under earlier registry pins cannot be resent before approval, so clear it with `wallet operation resolve <id> --replace` if it does not confirm. Approval disables policy until reviewed again. Setup then offers registry permissions even if you keep your current limits, and if the registry moved to a new proxy, it offers the link permission for the new address while keeping your allowed Portal accounts and other limits. Registry configuration is optional, without defaults, so old configuration and policy MACs remain valid. Adding the registry changes `manifestId`, not `networkId`.

If your wallet is on the older account implementation, run `wallet upgrade-implementation` first, then the commands above. Implementation upgrades cannot also change capabilities. Backups from before the registry restore with `wallet restore --in`, followed by the same steps.

The manifest pins the proxy and implementation bytecode, implementation slot and EIP-712 domain. These are checked before every registry operation and at capability approval, not at startup. After a registry upgrade, registry tools return `registry_verification_failed` and capability approval fails until a reviewed capability update, while transfers, swaps and reconciliation continue. A release with new registry pins does not stop other wallet use either: registry tools report `capability_manifest_unapproved` until you run `wallet capabilities approve`, with no config file needed. The wallet stores only manifest IDs, so that review can't show the old pins: it notes that different pins were approved before and shows the new ones as added. `registry_rpc_unavailable` is temporary: retry the same request. No retired registry is used.

## Expiry and cancellation

Registry consent nonces are separate from EntryPoint nonces. Every link increments both participants' registry nonces, including a parent's other-agent changes. Obtain approvals one at a time. A stale or invalid parent approval requires signing again in Portal. If consent goes bad while a request awaits local approval, the next `link_agent` retry returns the error and closes that request as `failed`; `wallet approve` returns the same error but leaves the request pending. Use a fresh approval with a new request UUID. A temporary RPC failure closes nothing, so the same request can be retried. It may show `approval_required` with `last_error: registry_rpc_unavailable` or `rpc_unavailable`; terminal approval is only needed if `reasons` lists a policy exception. A request ID that already holds an approval must be retried rather than replaced, and one approval allows at most eight request IDs.

If an operation succeeds on-chain but its registry event can't be found, it settles as `confirmed` with `registry_error: registry_event_missing`; check `get_agent_registry_status` before relying on it. A failed on-chain execution consumes the user-operation nonce and gas but does not consume registry consent. If abandoning the approval, use Portal's **Cancel outstanding approvals**, which sends `invalidateNonce()` from the parent and invalidates all its pending approvals. Clearing JSON or cancelling a local request does not revoke on-chain consent.

An uncertain submission retains signed bytes, nonce ownership and gas reservations. Do not change its approval under the same UUID. Resolve/reconcile the original signed request before submitting a fresh one. An expired signed link can still be mined as a reverting operation, so its reservations cannot simply be discarded. Use the existing same-nonce resolution/replacement workflow when needed. A replacement uses the original gas token, so a token-funded wallet does not need CENT to cancel a stale link. If the bundler keeps refusing a signed token-paid replacement, for example after the paymaster's terms change, one native replacement can follow it with `wallet operation resolve <request_id> --replace --native-gas`. It is priced above every operation already signed at that nonce. The token-paid replacement is kept and still checked for a receipt, so up to three operations can hold gas reservations. All stay held until the winning receipt; settlement releases the losing operations' reservations.

There is no way to disconnect from MCP or Portal. An unlink request recorded by an earlier build still reconciles if it was already sent, but is never prepared, approved or sent again: a signed one that was never sent must be cleared with `wallet operation resolve <request_id> --replace`.

Confirmation requires a canonical confirmed receipt and its matching EntryPoint event. The expected registry event is then looked for inside that user operation's execution log interval, after `BeforeExecution` or the previous operation event. If it isn't there, the operation still settles and reports `registry_event_missing` rather than blocking the wallet. A different operation in the same bundle cannot supply the event. All writes use `executeBatch`, so TransferGate rejection reverts execution.

## Validation

Offline suites cover approval parsing, EIP-191 bytes, ERC-1271 preflight, identity/domain pins, first-operation eligibility, intent tampering, local authorization, nonce races, retries, gas accounting, migration and event correlation. Public deployment bytecode vectors were read from the proxy and implementation on 2026-11-02.

For a real-contract test without public transactions:

```sh
anvil --fork-url https://rpc.incentiv.io --chain-id 24101 --port 18545
node --import tsx scripts/test-agent-registry-fork.mjs
```

The script verifies loopback and Anvil before sending, and tests through the real EntryPoint on the local fork: deployment/link, after which MCP refuses to unlink and the link stays; a stale parent approval for a second agent after the first link consumed the parent's nonce; `sign_agent_link` consent with the link sent by the parent account, as Portal does, which MCP's status then shows and cannot unlink; a USDC-paid first operation that deploys and links the agent through the real token paymaster, priced at a quarter of mainnet's base fee to show that the paymaster's USDC schedule, not the base fee, sets the charge; and a WCENT-paid first operation that deploys and links another agent through the paymaster's live USDC-to-WCENT quote. On the fork only, it impersonates a USDC holder and the paymaster owner, to fund the agent and trust the test's submitter as a bundler. The stale-consent case bypasses preflight deliberately and checks the canonical failed-operation receipt decoder; unit tests also verify the exposed `registry_error` and fresh-approval guidance. An Anvil fork does not reproduce Incentiv's passkey precompile, so passkey-signed Portal transactions are checked on mainnet.
