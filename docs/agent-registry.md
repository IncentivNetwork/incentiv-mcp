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

Save the previous complete network configuration before updating. With the proposed configuration selected, run:

```sh
incentiv-mcp wallet capabilities approve --previous /absolute/path/previous-config.json
incentiv-mcp setup
```

Approval preserves wallet identity, addresses, keys and journal history. It refuses unresolved signed operations and disables policy until reviewed again. Registry configuration is optional, without defaults, so old configuration and policy MACs remain valid. Adding the registry changes `manifestId`, not `networkId`.

If you still need the older account implementation upgrade, complete it using a complete configuration with the existing capabilities first. Approve the registry capability separately afterward; implementation upgrades cannot also change capabilities.

The manifest pins the proxy and implementation bytecode, implementation slot and EIP-712 domain. A registry upgrade requires a reviewed capability update. No retired registry is used.

## Expiry, cancellation and unlink

Registry consent nonces are separate from EntryPoint nonces. Every link/unlink increments both participants' registry nonces, including a parent's other-agent changes. Obtain approvals one at a time. A stale or invalid parent approval requires signing again in Portal.

A failed on-chain execution consumes the user-operation nonce and gas but does not consume registry consent. If abandoning the approval, use Portal's **Cancel outstanding approvals**, which sends `invalidateNonce()` from the parent and invalidates all its pending approvals. Clearing JSON or cancelling a local request does not revoke on-chain consent.

An uncertain submission retains signed bytes, nonce ownership and gas reservations. Do not change its approval under the same UUID. Resolve/reconcile the original signed request before submitting a fresh one. An expired signed link can still be mined as a reverting operation, so its reservations cannot simply be discarded. Use the existing same-nonce resolution/replacement workflow when needed.

Call `unlink_agent` with the expected parent to disconnect locally. Portal lists agents with individual **Disconnect** actions, and shows an account linked as an agent with its own disconnect action. Unlink needs no consent signature from the other side.

Confirmation requires a canonical confirmed receipt, its matching EntryPoint event and the expected registry event inside that user operation's log interval. A different operation in the same bundle cannot supply confirmation. All writes use `executeBatch`, so TransferGate rejection reverts execution.

## Validation

Offline suites cover approval parsing, EIP-191 bytes, ERC-1271 preflight, identity/domain pins, first-operation eligibility, intent tampering, local authorization, nonce races, retries, gas accounting, migration and event correlation. Public deployment bytecode vectors were read from the proxy and implementation on 2026-11-02.

For a real-contract test without public transactions:

```sh
anvil --fork-url https://rpc.incentiv.io --chain-id 24101 --port 18545
node --import tsx scripts/test-agent-registry-fork.mjs
```

The script verifies loopback and Anvil before sending, and tests deployment/link, unlink and stale approval through the real EntryPoint on the local fork. A real browser passkey ceremony remains a prod-staging acceptance check; an Anvil fork does not reproduce Incentiv's passkey precompile.
