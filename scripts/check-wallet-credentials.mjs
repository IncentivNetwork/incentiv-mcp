// Optional native integration check. Only touches its unique temporary service.
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { nativeCredentials } from "../src/wallet/credentials.ts";

const store = await nativeCredentials(`io.incentiv.mcp.test.${randomUUID()}`);
const key = randomBytes(32);
try {
  await store.create("roundtrip", key);
  const loaded = await store.read("roundtrip");
  try { assert.ok(loaded?.equals(key), "Native credential round trip failed"); }
  finally { loaded?.fill(0); }
  await store.remove("roundtrip");
  const removed = await store.read("roundtrip");
  try { assert.ok(removed === undefined, "Native test credential was not removed"); }
  finally { removed?.fill(0); }
  console.log("Native credential write/read/delete passed.");
} finally {
  key.fill(0);
  await store.remove("roundtrip");
}
