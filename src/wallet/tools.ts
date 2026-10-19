import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ToolDoc } from "../tools.js";
import { WalletError } from "./keystore.js";
import { NetworkError } from "../network.js";
import type { WalletService } from "./service.js";

export function registerWalletTools(server: McpServer, wallet: WalletService): ToolDoc[] {
  const catalog: ToolDoc[] = [];
  const add = (name: string, description: string, shape: Record<string, z.ZodType>, readOnly: boolean, handler: (args: Record<string, unknown>) => Promise<unknown>) => {
    catalog.push({ name, description, readOnly, params: Object.entries(shape).map(([name, schema]) => ({ name, required: !schema.isOptional() })) });
    server.registerTool(name, { description, inputSchema: z.strictObject(shape), annotations: { readOnlyHint: readOnly, destructiveHint: !readOnly, idempotentHint: true, openWorldHint: true } }, async args => {
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
  return catalog;
}
