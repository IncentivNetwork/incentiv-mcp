import assert from "node:assert/strict";
import test from "node:test";
import { createCipheriv, hkdfSync, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { MAINNET } from "../src/config.ts";
import { previousImplementationConfig } from "../src/account-upgrade.ts";
import { authenticateWallet, ownerAddress, parseEnvelope, sealWallet, walletAad } from "../src/wallet/keystore.ts";

// Public, deliberately unsafe test keys; never fund the corresponding account.
const ownerKey = Buffer.alloc(32); ownerKey[31] = 1;
const wrappingKey = Buffer.alloc(32, 0x42);
const binding = { schemaVersion: 1, walletId: randomUUID(), creationToken: randomUUID(), storage: "file" };
const envelope = () => sealWallet(MAINNET, binding, ownerKey, wrappingKey);

test("keystore v1 published vector authenticates and matches independent AES/HKDF calculation", () => {
  const vector = JSON.parse(readFileSync(new URL("./fixtures/wallet-v1.json", import.meta.url), "utf8"));
  const wallet = parseEnvelope(vector.envelope);
  const key = Buffer.from(vector.wrappingKeyHex, "hex");
  assert.equal(walletAad(wallet).toString("utf8"), vector.aadUtf8);
  const aes = Buffer.from(hkdfSync("sha256", key, Buffer.from(wallet.keyDerivation.salt, "base64"), wallet.keyDerivation.info, 32));
  assert.equal(aes.toString("hex"), vector.derivedAesKeyHex);
  const cipher = createCipheriv("aes-256-gcm", aes, Buffer.from(wallet.cipher.nonce, "base64"));
  cipher.setAAD(Buffer.from(vector.aadUtf8));
  assert.equal(Buffer.concat([cipher.update(Buffer.from(vector.ownerKeyHex, "hex")), cipher.final()]).toString("base64"), wallet.cipher.ciphertext);
  assert.equal(cipher.getAuthTag().toString("base64"), wallet.cipher.tag);
  authenticateWallet(previousImplementationConfig(MAINNET), wallet, key);
  assert.equal(ownerAddress(ownerKey), "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
  key.fill(0); aes.fill(0);
});

test("fresh encryptions use independent HKDF salts and GCM nonces", () => {
  const a = envelope(), b = envelope();
  assert.notEqual(a.keyDerivation.salt, b.keyDerivation.salt);
  assert.notEqual(a.cipher.nonce, b.cipher.nonce);
  assert.notEqual(a.cipher.ciphertext, b.cipher.ciphertext);
  authenticateWallet(MAINNET, a, wrappingKey);
  authenticateWallet(MAINNET, b, wrappingKey);
  assert.equal(ownerKey[31], 1, "caller owns and clears the input key");
});

test("authenticated metadata, nonce, ciphertext, tag and wrapping key cannot be substituted", () => {
  const original = envelope();
  const mutate = [
    (e) => { e.walletId = randomUUID(); },
    (e) => { e.owner = "0x0000000000000000000000000000000000000001"; },
    (e) => { e.account = "0x0000000000000000000000000000000000000001"; },
    (e) => { e.keyStorage.creationToken = randomUUID(); },
    (e) => { e.keyStorage.kind = "credential-store"; },
    (e) => { e.keyDerivation.salt = Buffer.alloc(16).toString("base64"); },
    (e) => { e.cipher.nonce = Buffer.alloc(12).toString("base64"); },
    (e) => { e.cipher.ciphertext = Buffer.alloc(32).toString("base64"); },
    (e) => { e.cipher.tag = Buffer.alloc(16).toString("base64"); },
  ];
  for (const change of mutate) {
    const changed = structuredClone(original); change(changed);
    assert.throws(() => authenticateWallet(MAINNET, parseEnvelope(changed), wrappingKey), { code: "keystore_authentication_failed" });
  }
  assert.throws(() => authenticateWallet(MAINNET, original, Buffer.alloc(32)), { code: "keystore_authentication_failed" });
  assert.throws(() => authenticateWallet(MAINNET, original, Buffer.alloc(31)), { code: "wrapping_key_invalid" });
  const network = structuredClone(original); network.networkIdentity.networkId = `0x${"12".repeat(32)}`;
  assert.throws(() => authenticateWallet(MAINNET, network, wrappingKey), { code: "wallet_network_mismatch" });
  const manifest = structuredClone(original); manifest.approvedCapabilityManifestId = `0x${"12".repeat(32)}`;
  assert.throws(() => authenticateWallet(MAINNET, manifest, wrappingKey), { code: "capability_manifest_unapproved" });
});

test("unsupported format, algorithms, lengths, policy and extra fields fail closed", () => {
  const mutate = [
    (e) => { e.keyDerivation.name = "PBKDF2"; },
    (e) => { e.keyDerivation.info = "other-wallet"; },
    (e) => { e.keyDerivation.salt += "="; },
    (e) => { e.cipher.name = "AES-128-GCM"; },
    (e) => { e.cipher.tag = Buffer.alloc(12).toString("base64"); },
    (e) => { e.cipher.nonce = "invalid"; },
    (e) => { e.cipher.ciphertext = Buffer.alloc(31).toString("base64"); },
    (e) => { e.policy.enabled = true; },
    (e) => { e.policy.configured = true; },
    (e) => { e.salt = "1"; },
    (e) => { e.privateKey = "must never appear"; },
  ];
  for (const change of mutate) {
    const changed = envelope(); change(changed);
    assert.throws(() => parseEnvelope(changed), { code: "wallet_recovery_required" });
  }
  assert.throws(() => parseEnvelope({ ...envelope(), schemaVersion: 2 }), { code: "unsupported_wallet_version" });
});

test("even a valid authentication tag cannot authorize the wrong derived addresses", () => {
  const wallet = envelope();
  wallet.account = "0x0000000000000000000000000000000000000001";
  const aes = Buffer.from(hkdfSync("sha256", wrappingKey, Buffer.from(wallet.keyDerivation.salt, "base64"), wallet.keyDerivation.info, 32));
  const cipher = createCipheriv("aes-256-gcm", aes, Buffer.from(wallet.cipher.nonce, "base64"));
  cipher.setAAD(walletAad(wallet));
  wallet.cipher.ciphertext = Buffer.concat([cipher.update(ownerKey), cipher.final()]).toString("base64");
  wallet.cipher.tag = cipher.getAuthTag().toString("base64");
  aes.fill(0);
  assert.throws(() => authenticateWallet(MAINNET, wallet, wrappingKey), { code: "keystore_authentication_failed" });
});

// Run in a fresh process so earlier test imports cannot hide a circular dependency.
test("policy schemas can load before the keystore in a fresh process", async () => {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const policyUrl = new URL("../src/wallet/policy.ts", import.meta.url).href;
  await promisify(execFile)(process.execPath, ["--import", "tsx", "--input-type=module", "-e",
    `const policy = await import(${JSON.stringify(policyUrl)}); if (!policy.adminSchema || !policy.limitsSchema) throw new Error('Policy schemas missing');`,
  ], { timeout: 30000 });
});
