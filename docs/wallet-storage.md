# Local wallet storage and CLI

The local wallet is wired into stdio and the interactive CLI. HTTP remains
keyless. Policy administration, backup/restore, validation, signing, authenticated
journaling and retry/replacement handling are implemented. Signing happens only
under the authenticated policy.

`localWalletStore(config).createOrLoad()` creates or authenticates the one wallet
at `~/.incentiv-mcp/wallet`. It returns verified public metadata with
`status: "locked"`, `reason: "policy_not_configured"`, and a disabled, unconfigured
policy for a new wallet. Constructing the store or importing its modules does not access storage.
The production factory fixes the path within an explicit local startup profile and uses the live network verifier;
the injectable constructor is for isolated tests, not an MCP configuration option.

`--wallet-profile NAME` selects a separate wallet at
`~/.incentiv-mcp-profile-NAME/wallet` with credential service
`io.incentiv.mcp.wallet.v1.profile.NAME`. The default profile retains the original
path and `io.incentiv.mcp.wallet.v1` service. Profile names cannot be paths, are
case-sensitive lowercase identifiers, and are fixed before CLI/MCP startup.
Selecting a profile never moves keys, copies policy, transfers funds, or removes
the original wallet. Each profile keeps its own immutable creation anchor and
operation journal. A restore into another profile still requires disabling every
other copy of that same account before enabling it.

## Custody and permissions

The default wrapping-key backend is the native OS credential store through the
exact dependency `@napi-rs/keyring@2.1.0`: Windows Credential Manager, macOS
Keychain, or Linux Secret Service. Linux explicitly requests Secret Service;
there is no implicit fallback to the transient kernel keyring or a file.
An unavailable or locked service returns `wallet_locked`.

Setting `INCENTIV_ALLOW_FILE_KEY=1` explicitly selects file-key mode for a new
wallet. An existing wallet keeps its recorded backend; this flag never migrates
it. Every load of a file-key wallet requires the flag. Its `master.key` is a
random 32-byte wrapping key, not the owner key. The public result warns that a
copy of the wallet directory contains everything needed to unlock it and that
file-key mode cannot protect against a shell-capable agent using the same OS user.

Every load checks the wallet tree's permissions. POSIX paths must belong to the
current user and have mode `0700` for directories or `0600` for files. Windows
requires protected owner-only DACLs. Symlinks, junctions/reparse points, hard-linked
files, unexpected root artifacts, and unsafe parent aliases are rejected. Existing
permissions are never silently repaired. New secret files are protected before
secret bytes are written.

Windows ACL operations are in the inspectable
[`windows-permissions.ps1`](../src/wallet/windows-permissions.ps1) asset, copied
alongside compiled code by `npm run build`. It receives only public paths/actions
on stdin and runs with `-File` under the normal execution policy. It does not use
encoded commands, execution-policy bypasses, or antivirus exclusions. A blocked
script or failed ACL check produces `wallet_permissions_invalid`.

Each Node process reuses one PowerShell helper over private stdin/stdout pipes;
every request reads the current ACLs and reparse-point attributes again. Permission
results are never cached. A malformed response, pipe failure, helper exit or
20-second request timeout rejects outstanding operations. The helper closes after
30 seconds idle or when its parent exits; it never keeps an idle CLI alive. No
wallet keys, passwords, file contents or network requests enter this helper.

## Keystore v1 and test vector

`wallet upgrade-implementation` is a local, password-confirmed transition for the
single reviewed IncentivAccount upgrade. It retains wallet ID, owner/account,
storage binding, wrapping key and all request IDs. An authenticated journal update
records the new network/manifest and the compatible pending-operation manifest
pair before the envelope is resealed. The journal retains its original network ID
and historical manifests, so an interruption between the two writes can be retried
with the same command. Pending signatures, replacement bytes and spending
reservations survive; all exception approvals are cleared and unsigned requests
are cancelled. Policy ends disabled. Ordinary loading and capability approval
still reject unrelated identity changes. The historical v1 cryptographic vector
is intentionally unchanged and authenticates against the previous configuration.

Old backups require `wallet restore --in FILE --upgrade-implementation`, recovery
and administration authentication, and an empty destination. The source backup is
never rewritten. New backups retain the authenticated network/manifest lineage.

The strict envelope schema is in [`keystore.ts`](../src/wallet/keystore.ts).
It accepts only schema version 1, HKDF-SHA256, AES-256-GCM, salt `"0"`, and a strict
disabled or configured policy. Configured policies include a separate scrypt
administration verifier authenticated by the envelope. Extra fields, unknown algorithms, and noncanonical
base64 or incorrect field lengths are rejected.

- Generate the 32-byte secp256k1 owner key and 32-byte wrapping key in memory.
- Derive a 32-byte AES key with HKDF-SHA256, a fresh 16-byte salt, and UTF-8 info
  `incentiv-mcp/wallet/v1`.
- Encrypt the owner key with AES-256-GCM, a fresh 12-byte nonce, and a 16-byte tag.
- Additional authenticated data is the UTF-8 RFC 8785 canonical serialization
  of the entire envelope with `cipher` replaced by `{"name":"AES-256-GCM"}`.
  This binds the full network identity, approved manifest ID, wallet ID, owner,
  account, account salt, policy, key-storage kind/creation token, and KDF metadata.
  The GCM operation authenticates the nonce and ciphertext separately.
- Before reading the wrapping key, verify network pins, approved capabilities,
  and the network identity. After decryption, recompute the owner and smart-account
  address locally, then compare them with the authenticated metadata.

[`test/fixtures/wallet-v1.json`](../test/fixtures/wallet-v1.json) publishes the
exact AAD, public test keys, derived AES key, nonce, ciphertext, and tag for
interoperability. **Those test keys are public; never fund their account.**
Regenerate the fixture with
`node --import tsx scripts/generate-wallet-vector.mjs`.

Secret buffers are cleared after use and private keys never enter storage
results, journals, subprocess arguments, or network requests. Node/V8, OpenSSL,
and native credential APIs do not guarantee complete memory zeroization.

## Creation, locking, and recovery

```text
~/.incentiv-mcp/
  wallet.create.lock             # exclusive process lock with heartbeat
  wallet.binding.json            # durable creation identity; retained
  wallet.commit.json             # permanent commit barrier for CLI-initialized wallets
  wallet.tmp-<wallet-id>/        # only during incomplete creation
  wallet/
    wallet.json                 # authenticated encrypted envelope
    public.json                 # replaceable display cache
    master.key                  # explicit file-key mode only
    disabled                    # emergency-stop marker, when present
    operations/
      journal.json              # authenticated atomic history and spend ledger
```

Creation first verifies the network, writes the immutable filesystem binding,
and, in OS-backed mode, writes a public `wallet-binding-v1` anchor under service
`io.incentiv.mcp.wallet.v1`. The anchor detects a lost filesystem tree without
enumerating or exposing other credentials. Then creation writes the wrapping key
under `pending:<wallet-id>:<creation-lock-token>` and builds the encrypted wallet
in a private staging directory. File-key mode puts `master.key` inside that same
directory. Files are flushed before the directory is renamed to `wallet`;
directory metadata is flushed where supported.

OS-backed creation then copies the key to
`wallet:<wallet-id>:<creation-lock-token>`, reloads and authenticates the committed
wallet, and only then removes the pending credential. File-key creation also
reloads and authenticates the committed files. Only after this succeeds is public
metadata returned. Repeated calls preserve the encrypted wallet and its addresses;
`public.json` is regenerated from authenticated data and never selects an address.

A valid staged or committed wallet with its matching pending credential resumes
without generating new keys. Incomplete/corrupt artifacts, conflicting credentials,
and orphan bindings remain intact for explicit recovery. The implementation never
automatically deletes an orphan key, repairs a keystore, or creates a replacement.
A readable OS anchor also prevents enabling file-key mode from bypassing a lost
OS-backed wallet. If all filesystem evidence is deleted and the OS store is
unavailable, explicit file-key mode cannot establish whether an old wallet existed;
this is not a backup or recovery mechanism.

The creation lock has a random token, host identity, PID, start timestamp, and
heartbeat. A timestamp older than 60 seconds permits recovery only if the lock
belongs to this host and the PID is provably absent. A live/reused PID is never
evicted. Recovery is serialized by an exclusive `wallet.create.recover.lock`.
Unverifiable ownership or an abandoned recovery lock requires inspection, not
automatic deletion. Contention is bounded and can return `wallet_locked`; retrying
uses the same wallet. The same root lock now serializes wallet sessions, policy
updates, backup snapshots and transaction/nonce handling. Sends reconcile pending
records before allocating a nonce. Emergency disable creates its marker without
waiting for this lock; sign and relay paths recheck it.

## Error codes

| Code | Meaning |
| --- | --- |
| `wallet_locked` | Credential service unavailable or another creator/recovery lock owns the wallet. |
| `wallet_permissions_invalid` | Permission/ACL verification or Windows helper execution failed. |
| `wallet_path_unsafe` | Symlink, reparse point, hard link, or wrong filesystem object type. |
| `file_key_not_allowed` | Existing file-key wallet lacks explicit opt-in. |
| `keystore_missing` | Creation evidence exists but the encrypted wallet is missing. |
| `wrapping_key_missing` / `wrapping_key_invalid` | No matching key, or an invalid key length. |
| `unsupported_wallet_version` | An explicit format migration is required. |
| `keystore_authentication_failed` | Authentication tag or locally rederived addresses disagree. |
| `wallet_network_mismatch` | Wallet identity differs from configured/pinned identity. |
| `capability_manifest_unapproved` | Capabilities differ from the wallet's approved manifest. |
| `wallet_recovery_required` | Other malformed, conflicting, incomplete, or inaccessible evidence. |

Storage errors do not include raw credential-provider or filesystem error payloads.

## Policy and recovery commands

```text
incentiv-mcp wallet policy configure
incentiv-mcp wallet doctor
incentiv-mcp wallet init
incentiv-mcp wallet capabilities approve --previous <config.json>
incentiv-mcp wallet recover
incentiv-mcp wallet approve <request-id>
incentiv-mcp wallet disable
incentiv-mcp wallet operation resolve <request-id>
incentiv-mcp wallet operation resolve <request-id> --replace
incentiv-mcp wallet backup --out <file>
incentiv-mcp wallet restore --in <file>
incentiv-mcp wallet migrate [1]
```

`policy configure` reads a policy JSON path interactively, displays its contents
and pending operations, asks for explicit confirmation, and requires the existing
administration passphrase (or establishes it on first setup). Copy and adjust
[wallet-policy.example.json](wallet-policy.example.json). Its empty recipient
allowlist permits no autonomous recipient; replace sample amounts with your explicit limits.
All amounts are integer raw token units: `1000000` is one unit of a 6-decimal token.
Token keys are `native` or pinned contract addresses. ERC-20 transfers need selector
`0xa9059cbb` under the token's `targets` entry; swaps additionally need the exact
router/token selectors and either explicit `trustedRpcOrigins` or two
administrator-attested independently operated RPC origins. Add the gas token to
the token limits too.

For automated use of the public RPC, add
`"trustedRpcOrigins": ["https://rpc.incentiv.io"]` during authenticated policy
configuration. This trusts that source; it does not claim operator independence.
Missing or empty trust preserves the original independent-source rule. Existing
v1 envelopes and backups are not rewritten on load. Permitted operations need no
per-operation terminal prompt once policy signing is enabled.

`wallet init` reads and displays the policy and establishes its administration
factor before creating keys. It starts disabled and creates an empty authenticated
journal. The binding includes a recovery verifier; a permanent filesystem and OS
credential commit barrier is written before the directory is committed. Recovery
authenticates that verifier and only discards incomplete creation attempts with no
commit evidence or complete staged keystore. Legacy/MCP-created orphan bindings
have no such proof and remain preserved. Complete staged keystores resume with
their original keys through `create_agent_wallet`.

Capability approval takes the previous complete configuration and compares it to
the currently configured proposal. It verifies all proposed pins/handshake before
unlocking, requires the administration factor and unchanged displayed review,
rejects pending signatures and any immutable identity change, and preserves all
history and consumed spend. The journal records an approved manifest before the
envelope activates it; interrupted updates remain retryable. Unsigned approvals
are cancelled and policy is disabled until reviewed again.

`wallet doctor` checks the network and the bundler without reading credentials
or wallet storage.

Passphrases must be at least 12 bytes and are entered through a no-echo TTY.
Arguments, environment variables and piped stdin are never accepted for them.
The administration factor is required to loosen policy, re-enable, approve exact
exceptions, export an encrypted backup or resolve/rebroadcast a stuck operation.
`disable` may run without a TTY and does not need the network or a passphrase.

Exception approval displays and binds the canonical intent, exact unsigned
operation/hash, gas/payment limits, and swap minimum/deadline for at most five
minutes. Retrying the same request ID consumes that exact approval. Replacement
review builds a zero-value self-transfer at the original nonce with native gas;
either original or replacement may win. Both reservations remain until a verified
receipt resolves the nonce. Disabling prevents either from being rebroadcast.

Backup refuses while any operation owns a nonce. The portable bundle encrypts
the envelope, wrapping key and complete authenticated journal using scrypt
`N=131072,r=8,p=1,dkLen=32` and AES-256-GCM with fresh salt/nonce. It is reloaded,
decrypted and rederived before success is reported. It never overwrites an output
file. Restore refuses any existing wallet evidence, rechecks the network, uses
new local wrapping custody and the atomic creation protocol, and starts disabled.
Unsigned approvals are cancelled while preserving request IDs. Re-enable requires
acknowledging that source copies are disabled or destroyed and reconciling history
and the on-chain nonce. Cross-machine duplicate use cannot be prevented.

Migration to the already-current v1 format verifies it without changing the key
or account; unsupported targets fail without a keystore rewrite. Actual future
format migrations must retain a recoverable encrypted backup through verification.
