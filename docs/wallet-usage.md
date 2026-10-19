# Set up Incentiv in your AI app

## Local MCP: a wallet on your computer

### 1. Install

Install [Node.js](https://nodejs.org/) 22.18 or newer and reopen your terminal. These commands work in PowerShell on Windows and a terminal on macOS or Linux.

```sh
npm install --global --ignore-scripts incentiv-mcp
incentiv-mcp setup
```

The wizard registers the absolute Node and package paths; users do not need to calculate installation paths. Setup and wallet commands use the system certificate store on supported Node versions, with certificate verification enabled.

To run from a source checkout instead, use `npm ci --ignore-scripts`, `npm run build`, then `node --use-system-ca dist/index.js setup`, and replace `incentiv-mcp` in the commands below with `node --use-system-ca dist/index.js`.

### Existing wallets from the previous implementation

The package pins IncentivAccount 2.1.0, already active on mainnet. Check the upgrade state with:

```sh
incentiv-mcp wallet doctor
incentiv-mcp wallet upgrade-implementation
```

Use the same `--wallet-profile NAME` if your wallet is in a named profile. The
upgrade displays the old/new implementation and requires your existing
administration password in your terminal. An unconfigured wallet instead asks
you to choose a policy and administration password. Your account address, keys,
history and pending signed operations are preserved. The command sends no funds
and leaves sending disabled; check pending operations and review policy using
`setup` or `wallet policy configure` before enabling it again. Do not delete the
wallet or create a replacement to work around a mismatch. New wallets use the
current implementation directly.

For an old encrypted backup, restore into an empty profile with:

```sh
incentiv-mcp wallet restore --in PATH --upgrade-implementation
```

This requires both the backup recovery password and the existing administration
password. The original backup is preserved. Current backups use ordinary restore.
Keep every other copy of the same account disabled before enabling a restored copy.
An identity mismatch still blocks wallet access; do not bypass that check.

### 2. Follow setup in your own terminal

1. Choose **Codex**, **Claude Desktop**, **Cursor**, or manual configuration.
2. Wait for network identity and OS credential checks. Windows uses Credential Manager, macOS Keychain, and Linux an unlocked Secret Service session.
3. Create a wallet, or continue with the existing account. Rerunning setup preserves your account and operation history. A configured active wallet defaults to reconnecting the app; a disabled wallet defaults to finishing setup.
4. Choose assets and allowed recipients. CENT and USDC are the starter selection. An empty recipient list blocks transfers.
5. Enter your limits in ordinary amounts: `10` means ten tokens. Choose per-transfer/swap input, total daily budget **including gas**, maximum holdings, and maximum gas payment for each asset. Zero blocks that use; setup never chooses a spending allowance for you.
6. Choose whether to enable swaps and explicitly approve the displayed RPC sources. Review the gas ceiling and optional advanced settings. Default slippage and quote-deviation limits are 0.5%.
7. Choose and save an **administration password**, then a different **backup recovery password**. Each must be at least 12 bytes. The prompts show no characters while you type. Keep both passwords outside chat; there is no administration-password reset.
8. Choose a new backup filename in an existing directory. Setup encrypts, reloads and verifies the backup. Keep a copy away from this computer and store the passwords separately.
9. Review the permissions and confirm this is the only active wallet copy. Type `ENABLE` to allow requests within the policy. New wallets stay disabled if backup or activation is interrupted. Setup itself never sends funds.
10. Review the app connection and allow setup to save it. Conflicting entries require confirmation; other servers and settings are preserved. A protected configuration backup is created before changes to an existing file.

Your daily budget must cover both the transfer/swap input and gas in that asset. The underlying gas ceiling still applies when another token pays gas. Maximum holdings are checked separately: funding above that cap can block spending until you authenticate a policy change.

If setup cannot update an app automatically, it prints the exact configuration to copy. Claude Desktop local wallet setup supports Windows and macOS. Codex and Cursor can use the local server on Windows, macOS and Linux. Cloud sessions cannot access this computer's local wallet.

### 3. Confirm the connection

Restart your app, or reconnect its MCP server. Ask:

> Show the Incentiv network status, then show my Incentiv wallet balance.

Expected: the network is Incentiv Mainnet, and the wallet address matches the address shown by setup. The local server exposes 29 tools with the default mainnet configuration. App configuration being saved does not establish that the app connected; this first prompt verifies it.

### 4. Fund the wallet

Copy the **smart-account address shown by setup**, check the Incentiv Mainnet network, and fund it within the holdings limits you chose. Keep sufficient permitted gas tokens available. The first transaction also deploys the account; ask for a fresh unsigned estimate before funding for a particular operation. A quote is not permission to spend, and setup does not transfer or bridge funds for you.

The wallet can receive funds before deployment. Any EntryPoint gas deposit is reported separately from transferable CENT. Do not count that deposit as ordinary wallet balance.

### 5. Try a transfer or swap

Replace the capitalized placeholders with your own choices. These prompts authorize real operations when your policy permits them.

**Transfer**

> Send AMOUNT USDC to RECIPIENT from my Incentiv wallet, using a new request ID. Check its status and show the transaction link.

**Swap**

> Quote a swap of AMOUNT USDC to CENT. Show the minimum output and gas. Then swap within my configured limits using a new request ID and check its status.

**Pay gas in a token**

> Send AMOUNT USDC to RECIPIENT and pay gas in USDC. Use a new request ID and check its status.

Token-paid gas needs a nonzero gas allowance and sufficient daily budget in that token. Swaps need both assets in your policy and approved RPC trust. Your AI app may ask for its own confirmation in addition to the wallet policy.

**Pending operation**

> Check Incentiv request REQUEST_ID. If it is still pending, keep the same request ID and arguments.

A timeout does not mean a transfer failed. Never use a new request ID to retry an uncertain operation. Confirmed requests cannot execute again with the same ID. An `approval_required` result can be reviewed locally with `incentiv-mcp wallet approve REQUEST_ID`; that approval cannot override the maximum-holdings limit.

### Stop, back up, restore or change permissions

```sh
incentiv-mcp wallet disable
incentiv-mcp setup
incentiv-mcp wallet backup --out /absolute/path/to/new-backup.json
incentiv-mcp wallet restore --in /absolute/path/to/backup.json
```

On Windows, use an absolute path such as `C:\Users\YOU\Documents\incentiv-backup.json`. Quote any path containing spaces. Disable works without network access or the administration password; it stops new signing and rebroadcast, but cannot revoke a transaction already submitted.

Restore requires an empty wallet profile and starts disabled. Re-enable through setup only after disabling source copies. Never delete wallet files or credentials to force a restore or a new account. For a deliberately separate wallet, use the same profile on every command:

```sh
incentiv-mcp --wallet-profile second setup
incentiv-mcp --wallet-profile second wallet disable
```

The separate profile gets its own app connection. Default setup retains the original wallet. Advanced JSON administration, capability changes and recovery are documented in [wallet storage](wallet-storage.md).

## Troubleshooting

| What happened | Next step |
| --- | --- |
| `incentiv-mcp` is not found | Reopen the terminal after installation. Check `node --version` and your npm global executable path. |
| Node certificate error | Use `node --use-system-ca /absolute/path/to/dist/index.js setup`. Never disable certificate verification. |
| OS credentials unavailable | Unlock Keychain/Credential Manager or start an unlocked Linux Secret Service session, then rerun setup. |
| Network or bundler check failed | Run `incentiv-mcp wallet doctor`. Fix connectivity; never bypass an identity mismatch. |
| Backup failed or setup stopped | Keep all wallet files. Rerun setup, choose to finish permissions/backup, and use a new backup filename. |
| App cannot see the server | Restart it, check its MCP logs and generated absolute paths, then rerun setup to reconnect. |
| Invalid app configuration | Repair the reported JSON/TOML file or use the manual configuration. Setup preserves malformed files. |
| `wallet_permissions_invalid` | Use your own terminal and inspect directory permissions. Setup does not silently weaken or repair wallet ACLs. |
| Policy or gas limit blocks an operation | Review the quote and balances; authenticate a deliberate policy change through setup. |
| `operation_pending` | Check the existing request ID; do not start a second intent as a retry. |
| `wallet_recovery_required` | Preserve files and follow [authenticated recovery](wallet-storage.md); never delete the wallet to restart. |

Client references: [Codex](https://learn.chatgpt.com/docs/extend/mcp?surface=cli), [Claude Desktop](https://modelcontextprotocol.io/docs/2026-07-28/develop/connect-local-servers), [Cursor](https://cursor.com/docs/mcp). Historical local-test commands and machine-specific workarounds are in [development notes](wallet-development.md).
