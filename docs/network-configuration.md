# Network identity and capability configuration

The built-in network configuration in `src/mainnet.json` has four parts:

- `identity`: chain ID, genesis, EntryPoint, account factory, beacon and implementation pins, account version, derivation and signing schemes.
- `manifest`: the approved token, paymaster, router and bridge capabilities, including their contract code hashes.
- `accountCreationCode`: the unparameterized BeaconProxy creation bytecode, authenticated by the identity's `accountInitCodeHash`.
- `endpoints`: RPC arrays, bundler and explorer URLs. Endpoint changes do not change either ID.

All objects are validated strictly. Unknown fields, missing pins, inconsistent bridge routes/endpoints, conflicting hashes for the same contract, unsupported algorithms, and stale IDs are rejected. All core capabilities are required in schema v1; bridge support can be disabled. Disabled bridge configuration is never used for remote reads or broadcasts.

## Custom configuration

Copy the complete built-in JSON and edit it locally. Never generate trusted pins from a remote response. Verify contract addresses, code and the account derivation from independent deployment records before approving a new identity or manifest.

After intentional changes, calculate IDs in this order using the exported helper:

```js
import { configurationId, parseConfig } from './dist/config.js';

config.identity.networkId = configurationId(config.identity, 'networkId');
config.manifest.networkId = config.identity.networkId;
config.manifest.manifestId = configurationId(config.manifest, 'manifestId');
parseConfig(config); // validate before saving
```

IDs are `keccak256(UTF8(JCS(object without its own ID)))`, using RFC 8785 serialization. Address casing is part of the serialized content; the built-in file uses checksummed addresses. Keep amounts and salts out of numeric JSON fields when they exceed the safe integer range.

Set `INCENTIV_NETWORK_CONFIG` to the absolute file path. `INCENTIV_RPC_URL` replaces the local RPC array with one endpoint; use the JSON array to configure multiple sources. The other endpoint variables override their corresponding URL only. Individual chain/contract environment overrides are rejected in both transport modes, even when equal to the built-in value.

Startup verifies every configured Incentiv RPC chain ID, the local genesis hash, every enabled Incentiv code pin at a fixed block per endpoint (including local bridge contracts), the factory's beacon, the beacon's implementation, and an offline CREATE2 result against the factory. An unavailable local RPC or changed local contract fails startup. Remote RPCs and remote bridge pins are checked before any bridge tool or remote-chain broadcast runs; they do not gate an Incentiv-only wallet transfer or swap. Capability review/approval still verifies all local and remote pins. Ordinary startup never writes configuration or accepts new pins automatically. Capability code hashes pin runtime bytecode; they do not prove all mutable contract storage or all proxy implementations. The account beacon's implementation is checked explicitly.

Local stdio loads wallet tools. `verifyWalletSession` gates each wallet session: compare the existing wallet identity and approved manifest, then verify Incentiv RPCs before obtaining a wrapping key. Wallet intents only support strictly decoded local transfers/swaps; they cannot submit bridge calls. Remote verification stays mandatory at the public bridge boundary and during capability changes. Mismatches yield `wallet_network_mismatch`, `capability_manifest_unapproved`, or `network_verification_failed`. The wallet namespace helper always returns `~/.incentiv-mcp/wallet` and never creates or reads it. See [wallet release status](wallet-release.md) for the signing gate and remaining validation.

To approve changed capabilities, keep the previous complete configuration, set
`INCENTIV_NETWORK_CONFIG` to the proposal, and run `wallet capabilities approve
--previous <previous-config.json>`. The CLI verifies the proposed network, compares
both manifests, requires administration authentication and refuses pending signed
operations or any immutable identity change. Approval preserves the account and
history and disables policy until reviewed again. Ordinary startup never approves
a manifest. 
## Account derivation clarification

The verified factory uses:

```text
initializer = ABI(IncentivAccount.initialize(owner, [0, 0]))
initCode = BeaconProxy.creationCode || ABI(accountBeacon, initializer)
account = CREATE2(factory, bytes32(salt), keccak256(initCode))
```

The full init-code hash varies with the owner. Consequently `accountInitCodeHash` pins the **unparameterized proxy creation bytecode**, and the immutable identity additionally pins the beacon and account implementation. Runtime derivation appends constructor arguments locally. An implementation change remains an incompatible identity for ordinary sessions.

The CLI's `wallet upgrade-implementation` supports exactly the reviewed mainnet
transition from `0x43fb62a71d0Ce27FD6AB70347A438d67eC2DFC6C` to
`0x7F9Ff738B524a6A053Eb7bA1b89B37aF1CFE74c7` (IncentivAccount 2.1.0).
Its source/target network IDs are fixed in `src/account-upgrade.ts`; derivation,
factory, beacon, EntryPoint, signing and capability contents cannot change.
Only the implementation/version and the resulting network/manifest IDs change.
The proposed Incentiv network and its identity/manifest are verified before
accessing the wrapping credential. Implementation-only transitions retain all
remote capabilities unchanged, so remote bridge availability does not gate them;
capability approvals and bridge operations still verify remote networks.
No environment option can authorize another implementation. Existing wallets require explicit local administration approval;
the [wallet guide](wallet-usage.md#existing-wallets-from-the-previous-implementation)
also covers old backups.

Verified derivation vector: owner `0xb6204d2a6f872e96ed273fefbe9b3190099fa4f9`, salt `0`, account `0x2b2D67F51C5AE1e00eAeb1EA3C8A984a3bC9c8D6`.
