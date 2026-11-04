# Agent Registry connections

The mainnet proxy is `0x1Be49e07439A4c3B1B95E1A9ba1031f477306012`, chain ID 24101. This integration supports the agent-submitted flow: Portal signs parent consent; the local agent smart account sends `link` in an ERC-4337 v0.7 operation. No parent key enters MCP and no separate agent consent signature is exported.

## Connect

1. Run setup and fund your agent account for gas (native CENT, or an approved token through the paymaster).
2. Call `prepare_agent_link`. Open the returned first-party Portal `/agents` URL. A prod-staging reviewer can open the same `/agents` path and query on the prod-staging Portal origin; do not send signatures through a URL.
3. Check both full smart-account addresses. Portal reads the digest itself and signs its bytes using the EOA or passkey wrapper. Approvals last 15 minutes.
4. Copy the approval JSON into `link_agent` with a new `request_id` UUID, optional `gas_token` and `wait_for_confirmation`. This still requires authenticated local policy.
5. Reuse the same UUID only for identical retries. `get_agent_operation` reconciles the request; `get_agent_registry_status` reads the current relationship. Historical completion and the current relationship can differ after a later unlink.

The agent can be undeployed: factory deployment occurs before its first `link` executes. The parent must already be deployed. The local wallet checks account derivation, ownership and the allowed factory. Both sides must satisfy the registry roles and current limit.

## Local permissions

Setup can authorize selected Portal parent smart-account addresses and optional unlinking. The optional authenticated policy field is:

```json
"agentRegistry": {
  "parents": ["0xYOUR_PORTAL_SMART_ACCOUNT"],
  "allowUnlink": true
}
```

The registry's `link(address,address,uint256,bytes,uint256,bytes)` and `unlink()` selectors must also appear under its address in `targets`; setup adds the selected permissions. Existing policies grant neither operation. An out-of-policy request can use the existing exact-operation `wallet approve <request-id>` workflow in your terminal. Gas budgets, exposure limits, simulation, wallet disable and durable submission checks still apply. Registry calls transfer no business funds and reserve gas only. Never add arbitrary-call or arbitrary-digest signing permissions.

## Existing wallets

After updating, run:

```sh
incentiv-mcp wallet capabilities approve
incentiv-mcp setup
```

Transfers, swaps, reconciliation, backups and pending-operation commands keep working until you do; only the registry tools report `capability_manifest_unapproved`. Saving a policy or restoring a backup never approves the registry. The command derives the previous manifest by removing the registry from the active configuration. With a custom network that changes anything else, pass `--previous /absolute/path/previous-config.json`.

Approval preserves wallet identity, addresses, keys and journal history. It refuses unresolved signed operations, which you can check and resolve with the usual commands first, and disables policy until reviewed again. Setup then offers registry permissions even if you keep your current limits. Registry configuration is optional, without defaults, so old configuration and policy MACs remain valid. Adding the registry changes `manifestId`, not `networkId`.

If your wallet is on the older account implementation, run `wallet upgrade-implementation` first, then the commands above. Implementation upgrades cannot also change capabilities. Backups from before the registry restore with `wallet restore --in`, followed by the same steps.

The manifest pins the proxy and implementation bytecode, implementation slot and EIP-712 domain. These are checked before every registry operation and at capability approval, not at startup. After a registry upgrade, registry tools return `registry_verification_failed` and capability approval fails until a reviewed capability update, while transfers, swaps and reconciliation continue. A release with new registry pins does not stop other wallet use either: registry tools report `capability_manifest_unapproved` until you run `wallet capabilities approve`, with no config file needed. `registry_rpc_unavailable` is temporary: retry the same request. No retired registry is used.

## Expiry, cancellation and unlink

Registry consent nonces are separate from EntryPoint nonces. Every link/unlink increments both participants' registry nonces, including a parent's other-agent changes. Obtain approvals one at a time. A stale or invalid parent approval requires signing again in Portal. If consent goes bad while a request awaits local approval, the next `link_agent` retry returns the error and closes that request as `failed`; `wallet approve` returns the same error but leaves the request pending. Use a fresh approval with a new request UUID. A temporary RPC failure closes nothing, so the same request can be retried. It may show `approval_required` with `last_error: registry_rpc_unavailable` or `rpc_unavailable`; terminal approval is only needed if `reasons` lists a policy exception. A request ID that already holds an approval must be retried rather than replaced, and one approval allows at most eight request IDs.

If an operation succeeds on-chain but its registry event can't be found, it settles as `confirmed` with `registry_error: registry_event_missing`; check `get_agent_registry_status` before relying on it. A failed on-chain execution consumes the user-operation nonce and gas but does not consume registry consent. If abandoning the approval, use Portal's **Cancel outstanding approvals**, which sends `invalidateNonce()` from the parent and invalidates all its pending approvals. Clearing JSON or cancelling a local request does not revoke on-chain consent.

An uncertain submission retains signed bytes, nonce ownership and gas reservations. Do not change its approval under the same UUID. Resolve/reconcile the original signed request before submitting a fresh one. An expired signed link can still be mined as a reverting operation, so its reservations cannot simply be discarded. Use the existing same-nonce resolution/replacement workflow when needed. A replacement uses the original gas token, so a token-funded wallet does not need CENT to cancel a stale link. Both gas reservations stay held until the winning receipt; settlement releases the losing operation’s reservation.

Call `unlink_agent` with the expected parent to disconnect locally. Portal lists agents with individual **Disconnect** actions, and shows an account linked as an agent with its own disconnect action. Unlink needs no consent signature from the other side.

Confirmation requires a canonical confirmed receipt, its matching EntryPoint event and the expected registry event inside that user operation's execution log interval, after `BeforeExecution` or the previous operation event. A different operation in the same bundle cannot supply confirmation. All writes use `executeBatch`, so TransferGate rejection reverts execution.

## Validation

Offline suites cover approval parsing, EIP-191 bytes, ERC-1271 preflight, identity/domain pins, first-operation eligibility, intent tampering, local authorization, nonce races, retries, gas accounting, migration and event correlation. Public deployment bytecode vectors were read from the proxy and implementation on 2026-11-02.

For a real-contract test without public transactions:

```sh
anvil --fork-url https://rpc.incentiv.io --chain-id 24101 --port 18545
node --import tsx scripts/test-agent-registry-fork.mjs
```

The script verifies loopback and Anvil before sending, and tests deployment/link, unlink and stale approval through the real EntryPoint on the local fork. The stale-consent case bypasses preflight deliberately and checks the canonical failed-operation receipt decoder; unit tests also verify the exposed `registry_error` and fresh-approval guidance. A real browser passkey ceremony remains a prod-staging acceptance check; an Anvil fork does not reproduce Incentiv's passkey precompile.
