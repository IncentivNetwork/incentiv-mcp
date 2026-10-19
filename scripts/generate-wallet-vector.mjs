// Regenerate the PUBLIC interoperability fixture, never a real wallet.
import { createCipheriv, hkdfSync } from "node:crypto";
import { writeFileSync } from "node:fs";
import { MAINNET, canonicalJson } from "../src/config.ts";
import { deriveSmartAccount } from "../src/network.ts";

const ownerKey = Buffer.alloc(32); ownerKey[31] = 1;
const wrappingKey = Buffer.alloc(32, 0x42);
const owner = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";
const metadata = {
  schemaVersion: 1,
  walletId: "00000000-0000-4000-8000-000000000001",
  networkIdentity: MAINNET.identity,
  approvedCapabilityManifestId: MAINNET.manifest.manifestId,
  owner, account: deriveSmartAccount(MAINNET, owner), salt: "0",
  policy: { schemaVersion: 1, enabled: false, configured: false },
  keyStorage: { kind: "file", creationToken: "00000000-0000-4000-8000-000000000002" },
  keyDerivation: { name: "HKDF-SHA256", salt: Buffer.from([...Array(16).keys()]).toString("base64"), info: "incentiv-mcp/wallet/v1" },
};
const nonce = Buffer.from([...Array(12).keys()].map((n) => n + 16));
const aadUtf8 = canonicalJson({ ...metadata, cipher: { name: "AES-256-GCM" } });
const aes = Buffer.from(hkdfSync("sha256", wrappingKey, Buffer.from(metadata.keyDerivation.salt, "base64"), metadata.keyDerivation.info, 32));
const cipher = createCipheriv("aes-256-gcm", aes, nonce);
cipher.setAAD(Buffer.from(aadUtf8));
const ciphertext = Buffer.concat([cipher.update(ownerKey), cipher.final()]);
writeFileSync(new URL("../test/fixtures/wallet-v1.json", import.meta.url), JSON.stringify({
  warning: "PUBLIC TEST KEYS. Never fund this owner or account.",
  ownerKeyHex: ownerKey.toString("hex"), wrappingKeyHex: wrappingKey.toString("hex"),
  derivedAesKeyHex: aes.toString("hex"), aadUtf8,
  envelope: { ...metadata, cipher: { name: "AES-256-GCM", nonce: nonce.toString("base64"), ciphertext: ciphertext.toString("base64"), tag: cipher.getAuthTag().toString("base64") } },
}, null, 2) + "\n");
ownerKey.fill(0); wrappingKey.fill(0); aes.fill(0);
