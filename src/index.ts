#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { spawn } from "node:child_process";
import { loadConfig } from "./config.js";
import { verifyNetwork } from "./network.js";
import { Ctx } from "./context.js";
import { parseWalletProfileArgs } from "./wallet-profile.js";
import {
  VERSION,
  createLocalStdioMcpServer,
} from "./server.js";

async function runStdio(profile: string): Promise<void> {
  const ctx = new Ctx(loadConfig());
  await verifyNetwork(ctx.config, undefined, "local");
  const { server } = await createLocalStdioMcpServer(ctx, profile);
  await server.connect(new StdioServerTransport());
  // stdout belongs to the transport.
  console.error(
    `incentiv-mcp v${VERSION} on ${ctx.config.identity.name} — local stdio, wallet profile ${profile} under authenticated policy`,
  );
}

let launch;
try { launch = parseWalletProfileArgs(process.argv.slice(2)); }
catch (error) { console.error(error instanceof Error ? error.message : "Invalid startup arguments"); process.exit(1); }
const { args, profile } = launch;
if (args[0] === "--help" || args[0] === "-h" || (args[0] === "setup" && args[1] === "--help")) {
  console.log(`Incentiv MCP v${VERSION}

  incentiv-mcp setup                         Guided wallet setup and app connection
  incentiv-mcp --wallet-profile NAME setup   Set up a separate named wallet
  incentiv-mcp wallet doctor                 Check network and bundler without opening a wallet
  incentiv-mcp wallet upgrade-implementation Approve the supported account upgrade (starts disabled)
  incentiv-mcp wallet disable                Stop new signing and rebroadcast
  incentiv-mcp wallet backup --out FILE      Create a verified encrypted backup
  incentiv-mcp wallet restore --in FILE      Restore into an empty profile (starts disabled)
    Add --upgrade-implementation for a backup from the previous account implementation.
  incentiv-mcp wallet policy configure       Advanced policy JSON administration
  incentiv-mcp --version                     Show version

With no command, starts the local stdio MCP server. Node.js 22.18+ required.
Guide: https://github.com/IncentivNetwork/incentiv-mcp#readme
Setup never sends funds. Passwords are entered only in your own terminal.`);
} else if ((args[0] === "wallet" || args[0] === "setup") && process.allowedNodeEnvironmentFlags.has("--use-system-ca") && !process.execArgv.includes("--use-system-ca")) {
  // The installed command must trust the same OS certificate store as its app launcher.
  // Inherit the user's terminal; no passwords or wallet data cross this boundary.
  const child = spawn(process.execPath, [...process.execArgv, "--use-system-ca", process.argv[1], ...process.argv.slice(2)], { stdio: "inherit", windowsHide: true });
  child.on("error", () => { console.error("Could not start Node with the system certificate store. See incentiv-mcp --help."); process.exitCode = 1; });
  child.on("exit", code => { process.exitCode = code ?? 1; });
} else if (args[0] === "wallet" || args[0] === "setup") {
  const command = args[0] === "setup"
    ? import("./setup.js").then(m => m.runSetup(args.slice(1), profile))
    : import("./wallet/cli.js").then(m => m.runWalletCli(args.slice(1), profile));
  command.catch(e => {
    // Only explicitly typed wallet/network errors may cross the CLI boundary.
    console.error(e && typeof e.code === "string" && e.constructor?.name.endsWith("Error") && ["WalletError", "NetworkError"].includes(e.constructor.name) ? e.message : "Command failed. Existing wallet data was preserved. See https://github.com/IncentivNetwork/incentiv-mcp#readme");
    process.exitCode = 1;
  });
} else if (args[0] === "--version" || args[0] === "-v") {
  console.log(VERSION);
} else {
  runStdio(profile).catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
