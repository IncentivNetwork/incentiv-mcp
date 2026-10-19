# Incentiv MCP Server

A local [Model Context Protocol](https://modelcontextprotocol.io) server for the [Incentiv](https://incentiv.io) blockchain. It runs on your computer over stdio and includes an encrypted, policy-constrained wallet. Keys stay on your computer and never enter MCP inputs or outputs.

Version 0.3.0. Authenticated spending policy and all transaction checks stay mandatory.

## Install

Requires Node.js 22.18 or newer.

```sh
npm install --global --ignore-scripts incentiv-mcp
incentiv-mcp setup
```

Setup chooses your app, sets spending permissions, asks you to save two passwords (administration and backup recovery) and verifies your backup. Restart the app and ask: **“Show the Incentiv network status, then my wallet balance.”** Setup never sends funds.

Rerun `incentiv-mcp setup` to finish an interrupted setup or reconnect an existing wallet. Use `incentiv-mcp --wallet-profile second setup` only to create a separate wallet. Stop new signing at any time with `incentiv-mcp wallet disable`.

To run from a source checkout instead:

```sh
npm ci --ignore-scripts
npm run build
node --use-system-ca dist/index.js setup
```

See the [setup walkthrough](https://github.com/IncentivNetwork/incentiv-mcp/blob/main/docs/wallet-usage.md) for Codex, Claude Desktop, Cursor and other MCP clients, funding, a first transfer or swap, and recovery.

## Build, sign, broadcast

Chain tools never hold keys. A `build_*` tool returns the fully populated **unsigned** operation and `sign_hash`, the exact hash to sign. Your wallet, or any external signer you choose, signs it. A `broadcast_*` tool then relays the signed operation to the bundler or RPC. Local wallet transfers and swaps do the same steps on this computer, within your policy.

## Tools

| Group | Tools |
| --- | --- |
| Read — account | `get_account`, `get_smart_account`, `get_portfolio`, `get_account_activity`, `get_transactions`, `get_transfers` |
| Read — market | `list_assets`, `get_asset`, `get_swap_quote`, `get_gas_payment_options`, `get_network_status` |
| Read — explorer | `get_transaction`, `get_user_operation`, `get_block`, `search` |
| Build (unsigned) | `build_transfer`, `build_swap`, `build_transaction` |
| Bridge | `get_bridge_routes`, `build_bridge_transfer`, `build_bridge_transfer_out`, `get_bridge_status` |
| Broadcast (signed) | `broadcast_user_operation`, `broadcast_transaction` |
| Local wallet (stdio only) | `create_agent_wallet`, `get_agent_wallet`, `send_transfer`, `send_swap`, `get_agent_operation` |

Notable behaviors:

- Token arguments accept a symbol (`USDC`), an address, or `CENT` for native. Symbols resolve to the official bridged tokens. Ambiguous symbols return the candidate addresses.
- `build_transfer` and `build_swap` run Incentiv's on-chain **TransferGate** check on each call. They warn if a transfer would be escrowed (`PENDING`) or rejected, and return the gas quote before anything is signed.
- Swaps route through WCENT automatically, handle native CENT on either side (wrap and unwrap), and enforce `slippage_bps` (default 1%).
- `gas_token` (USDC, WETH, …) pays gas through Incentiv's Unified Token Paymaster. No CENT is required.
- Gas is estimated without a key. The server signs the estimation call with a throwaway ephemeral key that is never returned. The real owner signature is produced only on the client.
- The signing scheme is returned with every build: sign `sign_hash` as an EIP-191 personal message with the account owner key.

EOAs appear only where raw EVM data does (balances, and the plain-transaction history behind `get_transactions`). `get_account_activity` covers user-operation history and is empty for EOAs.

## Configuration

The server registers five wallet tools without touching storage until one is called. `wallet doctor` checks the network and bundler without opening a wallet. `wallet init` creates a disabled wallet, and `wallet policy configure` sets the administration password through a no-echo terminal prompt. `wallet backup --out <file>` writes an encrypted backup, and `wallet restore --in <file>` restores into an empty namespace. `wallet capabilities approve --previous <config.json>` approves new capabilities and keeps the account. See [wallet storage and CLI](https://github.com/IncentivNetwork/incentiv-mcp/blob/main/docs/wallet-storage.md).

Runtime dependencies are exact, and the full dependency graph is published in `npm-shrinkwrap.json`. Installation never runs a wallet migration.

The built-in network is defined in [src/mainnet.json](https://github.com/IncentivNetwork/incentiv-mcp/blob/main/src/mainnet.json): an immutable network identity, a versioned capability manifest, hash-pinned account creation bytecode, and independently replaceable endpoints. Both transports verify the RPC chain ID, genesis, contract code hashes, factory beacon, account implementation and account derivation before serving requests. Enabled bridge contracts are verified on their remote chains too. A failed check prevents startup.

Endpoint overrides keep that identity:

| Env var | Default | Purpose |
| --- | --- | --- |
| `INCENTIV_RPC_URL` | `https://rpc.incentiv.io` | JSON-RPC node. |
| `INCENTIV_BUNDLER_URL` | `https://bundler.incentiv.io` | ERC-4337 bundler. |
| `INCENTIV_EXPLORER_API_URL` | `https://explorer.incentiv.io/api/v2` | Blockscout v2 REST API. |
| `INCENTIV_EXPLORER_URL` | `https://explorer.incentiv.io` | Explorer for links. |
| `INCENTIV_NETWORK_CONFIG` | Built-in mainnet configuration | Absolute path to one complete network JSON file. |

Individual overrides such as `INCENTIV_CHAIN_ID`, `INCENTIV_ENTRY_POINT` or `INCENTIV_ACCOUNT_FACTORY` are rejected. Custom networks need a complete configuration with valid content-derived IDs; see [network configuration](https://github.com/IncentivNetwork/incentiv-mcp/blob/main/docs/network-configuration.md). Setting `manifest.bridge.enabled=false` removes the four bridge tools (20 public tools instead of 24).

## Data sources

The server reads from three first-party sources:

- **RPC** (`rpc.incentiv.io`): live state, native balances, `code`, nonces, contract reads (paymaster config, quotes, TransferGate, `BulkBalanceReader`) and gas estimation.
- **Bundler** (`bundler.incentiv.io`): ERC-4337 user-operation submission and gas estimation.
- **Explorer** (`explorer.incentiv.io/api/v2`, Blockscout v2 with its Account-Abstraction service): token list, transfers, transactions, blocks and user operations.

Token balances are always re-read on-chain. The explorer is used only to discover which tokens an account holds and to serve history. The balances in `get_portfolio` come from an on-chain `BulkBalanceReader` call, so a lagging indexer cannot produce a wrong balance.

## Development

```bash
npm install
npm run ci          # offline tests + typecheck
npm run build       # tsc -> dist/
node test-live.mjs  # live checks: keyless build yields a correct userOpHash; signing scheme
node test-mcp.mjs   # end-to-end: read, build (unsigned), client signs, broadcast
```

Built on `@modelcontextprotocol/sdk` and `viem`. The ERC-4337 v0.7 build path (packing, hashing, paymaster math, keyless gas estimation) is implemented against Incentiv's deployed contracts. The user-op hash and EIP-191 signature scheme are verified against the on-chain EntryPoint and SignatureVerifier in `test-live.mjs`.

## Automated local wallet

Configure the wallet policy once. Transfers and swaps within that policy then execute automatically through the local MCP, using the configured-RPC trust model. To use only the public Incentiv RPC for swaps, include `"trustedRpcOrigins": ["https://rpc.incentiv.io"]` in the policy you authenticate locally. Without it, independent-source verification is required. Private keys stay in local custody.
