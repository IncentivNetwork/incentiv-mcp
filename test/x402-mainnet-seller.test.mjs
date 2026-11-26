import assert from "node:assert/strict";
import test from "node:test";
import { decodePaymentRequiredHeader, decodePaymentResponseHeader, encodePaymentSignatureHeader } from "@x402/core/http";
import { FACILITATOR, NETWORK, SCHEME, startSeller } from "../scripts/x402-mainnet-seller.mjs";

test("mainnet test seller challenges unpaid requests and records identical paid replays", async t => {
  assert.equal(FACILITATOR, "https://x402.incentiv.io");
  const payTo = "0x00000000000000000000000000000000000000aa";
  const payer = "0x00000000000000000000000000000000000000bb";
  const transaction = `0x${"01".repeat(32)}`;
  let settles = 0;
  const facilitator = {
    getSupported: async () => ({ kinds: [{ x402Version: 2, network: NETWORK, scheme: SCHEME }], extensions: [], signers: {} }),
    verify: async () => ({ isValid: true, payer }),
    settle: async () => ++settles === 1 ? { success: true, transaction, network: NETWORK, payer }
      : { success: false, errorReason: "already_settled", transaction, network: NETWORK, payer },
  };
  const seller = await startSeller({ payTo, runId: "fixture", facilitator });
  t.after(seller.close);
  const url = seller.internal + seller.resource;
  const unpaid = await fetch(url);
  assert.equal(unpaid.status, 402);
  const required = decodePaymentRequiredHeader(unpaid.headers.get("payment-required"));
  await unpaid.body?.cancel();
  const [accepted] = required.accepts;
  assert.equal(required.x402Version, 2);
  assert.equal(accepted.amount, "10000");
  assert.equal(accepted.payTo, payTo);
  assert.equal(accepted.network, NETWORK);
  assert.equal(accepted.scheme, SCHEME);
  assert.equal(seller.seen.paid.length, 0);

  const payload = { x402Version: 2, resource: required.resource, accepted, payload: { userOperation: { sender: payer, signature: "0x01" } } };
  const payment = encodePaymentSignatureHeader(payload);
  const paid = await fetch(url, { headers: { "payment-signature": payment } });
  assert.equal(paid.status, 200);
  assert.deepEqual(await paid.json(), seller.fixture);
  assert.equal(decodePaymentResponseHeader(paid.headers.get("payment-response")).transaction, transaction);
  const reordered = encodePaymentSignatureHeader({ ...payload, payload: { userOperation: { signature: "0x01", sender: payer } } });
  assert.notEqual(reordered, payment);
  const replay = await fetch(url, { headers: { "payment-signature": reordered } });
  assert.equal(replay.status, 402);
  await replay.body?.cancel();
  assert.equal(seller.seen.unpaid, 1);
  assert.equal(seller.seen.paid.length, 2);
  assert.equal(seller.seen.paid[0], seller.seen.paid[1]);
  assert.notEqual(seller.seen.paid[0], payment);

  const changed = encodePaymentSignatureHeader({ ...payload, payload: { userOperation: { sender: payer, signature: "0x02" } } });
  const refused = await fetch(url, { headers: { "payment-signature": changed } });
  assert.equal(refused.status, 402);
  await refused.body?.cancel();
  assert.notEqual(seller.seen.paid[2], seller.seen.paid[0]);
});
