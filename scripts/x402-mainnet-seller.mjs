import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { promisify } from "node:util";
import express from "express";
import { HTTPFacilitatorClient, x402ResourceServer } from "@x402/core/server";
import { decodePaymentResponseHeader, decodePaymentSignatureHeader } from "@x402/core/http";
import { paymentMiddleware } from "@x402/express";
import { IncentivUserOpScheme } from "@incentiv/x402";

const exec = promisify(execFile);
export const FACILITATOR = "https://x402.incentiv.io";
export const NETWORK = "eip155:24101";
export const SCHEME = "incentiv-userop";
export const PRICE = "0.01";

function paymentFingerprint(header) {
  // The wallet journal may reorder JSON object keys between the first request and a replay.
  const canonical = JSON.stringify(decodePaymentSignatureHeader(header), (_key, value) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return value;
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]]));
  });
  return createHash("sha256").update(canonical).digest("hex");
}

export async function preflightSeller() {
  const response = await fetch(`${FACILITATOR}/supported`, { signal: AbortSignal.timeout(15_000), redirect: "error" });
  if (!response.ok) throw new Error(`Incentiv facilitator /supported returned HTTP ${response.status}`);
  const { kinds } = await response.json();
  if (!kinds?.some(k => k.x402Version === 2 && k.scheme === SCHEME && k.network === NETWORK)) {
    throw new Error("The Incentiv facilitator does not advertise the required mainnet payment scheme");
  }
  try { await exec("ssh", ["-V"], { timeout: 5_000 }); }
  catch { throw new Error("The automatic seller tunnel requires an OpenSSH client on PATH"); }
}

export async function startSeller({ payTo, runId, dropFirstSettlement = false, acceptPayments = true, facilitator = new HTTPFacilitatorClient({ url: FACILITATOR }) }) {
  const resource = `/e2e-${runId}`;
  const fixture = { test: "incentiv-mcp-x402-mainnet", runId };
  const seen = { unpaid: 0, paid: [], droppedSettlement: undefined };
  const app = express();
  app.set("trust proxy", "loopback"); // The seller listens on loopback behind its own HTTPS tunnel.
  const server = new x402ResourceServer(facilitator).register(NETWORK, new IncentivUserOpScheme());
  app.get(resource, (req, res, next) => {
    const signature = req.get("payment-signature");
    if (signature) seen.paid.push(paymentFingerprint(signature));
    else seen.unpaid++;
    if (signature && !acceptPayments) return res.sendStatus(403);
    if (signature && dropFirstSettlement && !seen.droppedSettlement) {
      const end = res.end.bind(res);
      res.end = (...args) => {
        // The x402 middleware buffers this response until the facilitator settles.
        const header = res.getHeader("payment-response");
        if (typeof header === "string") {
          const settlement = decodePaymentResponseHeader(header);
          if (!seen.droppedSettlement && settlement.success && settlement.transaction) {
            seen.droppedSettlement = settlement.transaction;
            return res.destroy();
          }
        }
        return end(...args);
      };
    }
    next();
  });
  app.use(paymentMiddleware({
    [`GET ${resource}`]: {
      accepts: [{ scheme: SCHEME, network: NETWORK, payTo, price: PRICE, maxTimeoutSeconds: 120 }],
      description: "Incentiv MCP release acceptance",
      mimeType: "application/json",
    },
  }, server));
  app.get(resource, (_req, res) => res.json(fixture));
  const listener = app.listen(0, "127.0.0.1");
  await once(listener, "listening");
  return {
    internal: `http://127.0.0.1:${listener.address().port}`, resource, fixture, seen,
    allowPayments: () => { acceptPayments = true; },
    close: () => new Promise((resolve, reject) => listener.close(error => error ? reject(error) : resolve())),
  };
}

export async function startTunnel(internal) {
  const temp = await mkdtemp(join(tmpdir(), "incentiv-x402-tunnel-"));
  const knownHosts = join(temp, "known_hosts");
  let child, closed, lines;
  const close = async () => {
    lines?.close();
    child?.kill();
    await closed;
    await rm(temp, { recursive: true, force: true });
  };
  try {
    // Ed25519 key verified against https://localhost.run/docs/security.
    await writeFile(knownHosts, "localhost.run ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILVqOuSMnyeGDVO1lG6EaG5In/dXABCchhmHKkuRU2s9\n", { mode: 0o600 });
    child = spawn("ssh", [
      "-F", "none", "-T", "-o", "BatchMode=yes", "-o", "PubkeyAuthentication=no", "-o", "IdentityAgent=none",
      "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "GlobalKnownHostsFile=none",
      "-o", `UserKnownHostsFile="${knownHosts}"`, "-o", "ExitOnForwardFailure=yes",
      "-R", `80:127.0.0.1:${new URL(internal).port}`, "nokey@localhost.run", "--", "--output", "json",
    ], { stdio: ["ignore", "pipe", "ignore"], windowsHide: true });
    closed = new Promise(resolve => child.once("close", resolve));
    lines = createInterface({ input: child.stdout });
    const origin = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => finish(new Error("Timed out registering the seller's HTTPS tunnel")), 30_000);
      const finish = (error, origin) => { clearTimeout(timer); if (error) reject(error); else resolve(origin); };
      lines.on("line", line => {
        let event;
        try { event = JSON.parse(line); } catch { return; }
        if (event.type !== "run.localhost.tunnel.registered") return;
        const host = event.data?.address;
        if (!/^[a-z0-9-]+(?:\.app)?\.lhr\.life$/.test(host ?? "")) return finish(new Error("Unexpected temporary seller hostname"));
        finish(null, `https://${host}`);
      });
      child.once("error", finish);
      child.once("exit", code => finish(new Error(`Seller tunnel exited with status ${code}`)));
    });
    return { origin, close };
  } catch (error) {
    await close();
    throw error;
  }
}
