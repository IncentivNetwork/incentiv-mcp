import { registryAddressSchema, registryApprovalSchema } from "../agent-registry.js";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ToolDoc } from "../tools.js";
import { WalletError } from "./keystore.js";
import { NetworkError } from "../network.js";
import type { WalletService } from "./service.js";

export function registerWalletTools(server: McpServer, wallet: WalletService): ToolDoc[] {
  const catalog: ToolDoc[] = [];
  // "sign" never changes chain state, but it hands out a signature that cannot be withdrawn, so clients
  // should still confirm it, and each call signs anew rather than repeating the last result.
  const add = (name: string, description: string, shape: Record<string, z.ZodType>, kind: boolean | "sign", handler: (args: Record<string, unknown>) => Promise<unknown>) => {
    const readOnly = kind === true, signs = kind === "sign";
    catalog.push({ name, description, readOnly, signs, params: Object.entries(shape).map(([name, schema]) => ({ name, required: !schema.isOptional() })) });
    server.registerTool(name, { description, inputSchema: z.strictObject(shape), annotations: { readOnlyHint: readOnly, destructiveHint: !readOnly, idempotentHint: !signs, openWorldHint: true } }, async args => {
      try { return { content: [{ type: "text" as const, text: JSON.stringify(await handler(args)) }] }; }
      catch (error) {
        const known = error instanceof WalletError || error instanceof NetworkError;
        return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ code: known ? error.code : "validation_failed", message: known ? error.message : "Local wallet operation failed" }) }] };
      }
    });
  };
  const common = { request_id: z.string().uuid(), gas_token: z.string().max(64).optional(), wait_for_confirmation: z.boolean().default(false) };
  const amount = z.string().max(100).regex(/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/);
  add("create_agent_wallet", "Create or verify the local encrypted wallet selected by the startup profile. New wallets cannot send until interactive authenticated policy setup.", {}, false, () => wallet.create());
  add("get_agent_wallet", "Verified local addresses, balances, policy, gas options and pending reservations. Exact gas readiness requires a send intent.", {}, true, () => wallet.get());
  add("send_transfer", "Locally validate, policy-check, sign, durably journal and relay a transfer. Retain and reuse the same request UUID on retries.", { ...common, token: z.string().max(64), to: z.string().regex(/^0x[0-9a-fA-F]{40}$/), amount }, false, args => wallet.send("transfer", args));
  add("send_swap", "Automatically swap within policy using explicitly trusted RPC origins or independent quote sources, an absolute minimum output and fresh local validation. Retain the request UUID on retries.", { ...common, token_in: z.string().max(64), token_out: z.string().max(64), amount_in: amount, minimum_out: amount, slippage_bps: z.number().int().min(0).max(1000).optional(), fee_tier: z.number().int().min(1).max(1_000_000).optional() }, false, args => wallet.send("swap", args));
  add("get_agent_operation", "Reconcile a journaled request using its UUID or user-operation hash. Never submits or rebroadcasts.", { id: z.union([z.string().uuid(), z.string().regex(/^0x[0-9a-fA-F]{64}$/)]) }, true, args => wallet.operation(String(args.id)));
  add("get_agent_registry_status", "Read this local smart account's registry relationship and optional parent eligibility.", { parent: registryAddressSchema.optional() }, true, args => wallet.registryStatus(args.parent as string | undefined));
  add("prepare_agent_link", "Get the first-party Portal connection URL for this smart account, for a parent approval to pass to link_agent. Does not sign or submit.", {}, true, () => wallet.prepareAgentLink());
  add("sign_agent_link", "Sign this deployed agent's consent to one parent allowed by local wallet policy, and get the Portal URL through which the user submits the connection from that parent. Never submits, but the consent cannot be withdrawn before it expires.", { parent: registryAddressSchema }, "sign", args => wallet.signAgentLink(args.parent as string));
  add("link_agent", "Connect this agent smart account using a Portal parent approval. Local authenticated policy and gas limits apply. Reuse the request UUID for identical retries; stale approval needs re-signing in Portal.", { ...common, approval: registryApprovalSchema }, false, args => wallet.send("link_agent", args));
  add("unlink_agent", "Unlink this agent from the expected parent. Requires local policy authorization. Retain the same UUID for retries.", { ...common, parent: registryAddressSchema }, false, args => wallet.send("unlink_agent", args));
  return catalog;
}
