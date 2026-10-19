import { homedir } from "node:os";
import { join } from "node:path";

/** A local startup choice, never a network configuration or MCP tool argument. */
export function walletProfile(profile = "default") {
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(profile) || profile.endsWith("-")) {
    throw new Error("Wallet profile must be 1-32 lowercase letters, digits or hyphens, starting with a letter and ending with a letter or digit");
  }
  return {
    name: profile,
    root: join(homedir(), profile === "default" ? ".incentiv-mcp" : `.incentiv-mcp-profile-${profile}`),
    credentialService: profile === "default" ? "io.incentiv.mcp.wallet.v1" : `io.incentiv.mcp.wallet.v1.profile.${profile}`,
  };
}

export function parseWalletProfileArgs(input: string[]) {
  const explicit = input[0] === "--wallet-profile";
  if (explicit && !input[1]) throw new Error("Use --wallet-profile <name> before the wallet command");
  const profile = walletProfile(explicit ? input[1] : "default").name;
  const args = input.slice(explicit ? 2 : 0);
  if (args.some(arg => arg === "--wallet-profile" || arg.startsWith("--wallet-profile="))) {
    throw new Error("Specify --wallet-profile <name> once, before the wallet command");
  }
  if (args.length && !["wallet", "setup", "--help", "-h", "--version", "-v"].includes(args[0])) throw new Error("Unknown command; run incentiv-mcp --help");
  return { profile, args };
}
