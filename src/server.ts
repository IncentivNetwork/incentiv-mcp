import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Ctx } from "./context.js";
import { renderMarkdown } from "./docs.js";
import { registerPublicTools, type ToolDoc } from "./tools.js";

export const VERSION = "0.2.0";

export interface ServerCapabilities {
  readonly publicTools: true;
  readonly walletTools: true;
}

export interface ServerBundle {
  capabilities: ServerCapabilities;
  server: McpServer;
  catalog: ToolDoc[];
}

const CAPABILITIES: ServerCapabilities = Object.freeze({
  publicTools: true,
  walletTools: true,
});

export function makeServer(ctx: Ctx, registerWallet: (server: McpServer) => ToolDoc[]): ServerBundle {
  if (typeof registerWallet !== "function") throw new Error("The local server requires explicit wallet dependencies");

  const server = new McpServer({ name: "incentiv-mcp", version: VERSION });
  const catalog = [...registerPublicTools(server, ctx), ...registerWallet(server)];

  server.registerResource(
    "docs",
    "incentiv://docs",
    {
      title: "Incentiv MCP documentation",
      description: "How the local server works and every tool it exposes.",
      mimeType: "text/markdown",
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: "text/markdown",
          text: renderMarkdown(ctx.config, catalog),
        },
      ],
    }),
  );

  return { capabilities: CAPABILITIES, server, catalog };
}

export async function createLocalStdioMcpServer(ctx: Ctx, profile = "default"): Promise<ServerBundle> {
  const { WalletService } = await import("./wallet/service.js");
  const { localWalletStore } = await import("./wallet/store.js");
  const { registerWalletTools } = await import("./wallet/tools.js");
  const wallet = new WalletService(ctx, localWalletStore(ctx.config, profile));
  return makeServer(ctx, server => registerWalletTools(server, wallet));
}
