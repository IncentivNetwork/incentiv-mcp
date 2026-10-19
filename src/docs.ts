import type { Config } from "./config.js";
import { publicServiceUrl } from "./public-output.js";
import type { ToolDoc } from "./tools.js";
import { getBridgeConfig } from "./bridge.js";
import { onboardingHtml, onboardingScript, troubleshootingHtml } from "./onboarding-docs.js";
import { brandLogo, brandFonts } from "./brand-assets.js";
import { docsStyles } from "./docs-styles.js";

/**
 * Documentation rendered from the tool catalog, so it stays in step with the
 * registered tools. Served as an MCP resource and as a local HTML page.
 */

/** Grouping follows the tool naming. */
const GROUPS: { title: string; blurb: string; match: (t: ToolDoc) => boolean }[] = [
  {
    title: "Local wallet",
    blurb: "Configure policy once; permitted transfers and swaps then execute automatically within those limits.",
    match: (t) => ["create_agent_wallet", "get_agent_wallet", "send_transfer", "send_swap", "get_agent_operation"].includes(t.name),
  },
  {
    title: "Accounts & balances",
    blurb: "Any address, EOA or smart account. Balances are always read on-chain.",
    match: (t) => ["get_account", "get_smart_account", "get_portfolio", "get_account_activity", "get_transactions", "get_transfers"].includes(t.name),
  },
  {
    title: "Market data",
    blurb: "The token registry, DEX quotes, and what it costs to transact.",
    match: (t) => ["list_assets", "get_asset", "get_swap_quote", "get_gas_payment_options", "get_network_status"].includes(t.name),
  },
  {
    title: "Explorer",
    blurb: "Direct lookups by hash, number, or free-form query.",
    match: (t) => ["get_transaction", "get_user_operation", "get_block", "search"].includes(t.name),
  },
  {
    title: "Build — unsigned",
    blurb: "Returns a complete operation with an empty signature plus the hash to sign. Nothing is signed or sent.",
    match: (t) => t.name.startsWith("build_") && !t.name.startsWith("build_bridge"),
  },
  {
    title: "Bridge",
    blurb: "The official Incentiv Bridge, over Hyperlane warp routes.",
    match: (t) => t.name.includes("bridge"),
  },
  {
    title: "Broadcast — signed",
    blurb: "Relay operations you already signed.",
    match: (t) => t.name.startsWith("broadcast_"),
  },
];

function grouped(tools: ToolDoc[]): { title: string; blurb: string; tools: ToolDoc[] }[] {
  const seen = new Set<string>();
  const out = GROUPS.map((g) => {
    const list = tools.filter((t) => !seen.has(t.name) && g.match(t));
    list.forEach((t) => seen.add(t.name));
    return { title: g.title, blurb: g.blurb, tools: list };
  }).filter((g) => g.tools.length);
  const rest = tools.filter((t) => !seen.has(t.name));
  if (rest.length) out.push({ title: "Other", blurb: "", tools: rest });
  return out;
}

const esc = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** Markdown documentation, served as an MCP resource. */
export function renderMarkdown(cfg: Config, tools: ToolDoc[]): string {
  const { routes: ROUTES, remoteChains: REMOTE_CHAINS } = getBridgeConfig(cfg);
  const bridgeTokens = [...new Set(ROUTES.map((r) => r.token))];
  const lines: string[] = [
    `# Incentiv MCP Server`,
    ``,
    `A local MCP server for the Incentiv blockchain (chain ${cfg.identity.chainId}, native ${cfg.identity.nativeSymbol}).`,
    `It exposes chain tools plus a local wallet. Private key material stays inside this local process and is never returned through MCP.`,
    ``,
    `## Install`,
    ``,
    "```sh",
    "npm install --global --ignore-scripts incentiv-mcp",
    "incentiv-mcp setup",
    "```",
    ``,
    `Setup chooses your AI app, sets spending permissions, saves two passwords you enter in your own terminal, and verifies an encrypted backup. Setup never sends funds.`,
    ``,
    `Connect the app's MCP configuration to the installed command:`,
    ``,
    "```json",
    `{ "mcpServers": { "incentiv": { "command": "incentiv-mcp" } } }`,
    "```",
    ``,
    `Restart your app and ask: "Show the Incentiv network status, then show my Incentiv wallet balance."`,
    ``,
    `## How writing works`,
    ``,
    `Configure policy once in your own terminal. Permitted transfers and swaps then execute automatically within those limits. New and restored wallets start disabled. \`wallet disable\` stops new signing and rebroadcast.`,
    `Wallet sends require a stable request UUID. They enforce policy, validate locally, journal before submission, and retry identical signed bytes. Never ask the user for passwords in chat; the administration passphrase never enters MCP.`,
    ``,
    `Chain tools that do not hold keys work the same way: a \`build_*\` tool returns a complete unsigned operation and \`sign_hash\`, which an external signer may sign before a \`broadcast_*\` tool relays it.`,
    ``,
    `Accounts deploy on first use: an Incentiv smart account address exists and can receive funds before it is deployed. Pass \`owner\` to a build tool and the operation creates the account as it runs. Signing is by an ordinary EOA key; passkeys are not used.`,
    ``,
    ...(cfg.manifest.bridge.enabled ? [
      `## Bridge`,
      ``,
      `Tokens: ${bridgeTokens.join(", ")}. Chains: ${Object.values(REMOTE_CHAINS).map((c) => c.name).join(", ")}.`,
      `Bridging in costs a small amount of source-chain gas. Bridging out attaches the interchain fee as value in ${cfg.identity.nativeSymbol}, which a paymaster cannot sponsor — the account must hold it.`,
    ] : [`Bridge capability is disabled in this network configuration.`]),
    ``,
    `## Tools (${tools.length})`,
    ``,
  ];
  for (const g of grouped(tools)) {
    lines.push(`### ${g.title}`, ``);
    if (g.blurb) lines.push(g.blurb, ``);
    for (const t of g.tools) {
      const params = t.params.map((p) => (p.required ? p.name : `${p.name}?`)).join(", ") || "—";
      lines.push(`- **\`${t.name}\`** (${params})${t.readOnly ? "" : " — *changes chain state*"}`);
      if (t.description) lines.push(`  ${t.description}`);
    }
    lines.push(``);
  }
  lines.push(
    `## Endpoints this server reads`,
    ``,
    `- RPC \`${publicServiceUrl(cfg.endpoints.rpcUrls[0])}\` — live state and contract reads`,
    `- Bundler \`${publicServiceUrl(cfg.endpoints.bundlerUrl)}\` — ERC-4337 estimation and submission`,
    `- Explorer API \`${publicServiceUrl(cfg.endpoints.explorerApiUrl)}\` — indexed history and user operations`,
  );
  return lines.join("\n");
}

/**
 * The complete documentation as one self-contained HTML page. Everything is
 * inline: no external assets and no follow-up requests.
 */
export function renderHtml(cfg: Config, tools: ToolDoc[]): string {
  const { routes: ROUTES, remoteChains: REMOTE_CHAINS } = getBridgeConfig(cfg);
  const bridgeTokens = [...new Set(ROUTES.map((r) => r.token))];
  const chainNames = Object.values(REMOTE_CHAINS).map((c) => c.name);

  const walletNames = new Set(["create_agent_wallet", "get_agent_wallet", "send_transfer", "send_swap", "get_agent_operation"]);
  const chainTools = tools.filter(tool => !walletNames.has(tool.name));
  const toolHtml = grouped(chainTools)
    .map(
      (g) => `
      <div class="group">
        <div class="ghead"><h3>${esc(g.title)}</h3><span class="count">${g.tools.length} tool${g.tools.length === 1 ? "" : "s"}</span></div>
        ${g.blurb ? `<p class="gblurb">${esc(g.blurb)}</p>` : ""}
        <div class="cards">
          ${g.tools
            .map(
              (t) => `<details class="tool-entry">
            <summary>${esc(t.name)}<span class="tool-kind">${t.readOnly ? "Read / prepare" : "Submit"}</span></summary>
            <p>${esc(t.description ?? "")}</p>
            <div class="params">${
              t.params.length
                ? t.params.map((p) => `<span class="p${p.required ? "" : " opt"}">${esc(p.name)}${p.required ? "" : " (optional)"}</span>`).join("")
                : `<span class="p opt">no arguments</span>`
            }</div>
          </details>`,
            )
            .join("")}
        </div>
      </div>`,
    )
    .join("");

  // Bridge routes, grouped by token.
  const routeRows = bridgeTokens
    .map((tok) => {
      const rs = ROUTES.filter((r) => r.token === tok);
      const chains = rs.map((r) => REMOTE_CHAINS[r.chain].name).join(", ");
      const approve = rs[0].remoteStandard === "collateral" ? "Yes" : "No";
      const note =
        tok === "CENT"
          ? "Incentiv's own coin. Burns on the source chain, so bringing it in is a single transaction — the way to obtain CENT before bridging anything out."
          : rs[0].remoteStandard === "collateral"
            ? "The source chain escrows the canonical asset, so an approval comes first."
            : "Burns on the source chain; no approval needed.";
      return `<tr><td class="mono">${esc(tok)}</td><td>${esc(chains)}</td><td class="mono">${approve}</td><td class="muted">${esc(note)}</td></tr>`;
    })
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incentiv MCP | Local server</title>
<meta name="description" content="Install the Incentiv MCP server on your computer, keep wallet keys local, and connect Codex, Claude Desktop or Cursor.">
<style>${brandFonts}
${docsStyles}</style>
</head>
<body>
<a class="skip-link" href="#main">Skip to setup</a>
<div class="wrap">
<header class="topbar"><a class="brand" href="https://incentiv.io/" aria-label="Incentiv home">${brandLogo}<span>MCP</span></a><nav aria-label="Main navigation"><a href="#setup">Install</a><a href="#tools">Tools</a><a href="#troubleshooting">Help</a></nav></header>
<main id="main">
<div class="hero"><div><p class="eyebrow">Incentiv for AI apps</p><h1>Run Incentiv<br>on <em>your computer.</em></h1></div><p class="lede">A local MCP server connects your AI app to Incentiv's onchain tools. Your wallet keys stay on this computer, and every transaction follows the spending permissions you set.</p></div>
${onboardingHtml(chainTools.length + walletNames.size)}
${cfg.manifest.bridge.enabled ? `<section>
  <p class="kicker">Cold start</p>
  <h2>From funds on another chain to acting on Incentiv</h2>
  <p class="intro">An agent holding assets elsewhere can reach Incentiv without a person in the loop, and without holding ${esc(cfg.identity.nativeSymbol)} first. Every step is a build the agent signs itself.</p>
  <div class="seq">
    <div class="si"><div class="n">1</div><div>
      <h3>Find its account <span class="tag">server</span></h3>
      <p><span class="tool">get_smart_account</span> turns the agent's owner key into the account it controls. The address is deterministic and exists immediately — it can receive funds long before anything is deployed there.</p>
    </div></div>
    <div class="si"><div class="n">2</div><div>
      <h3>Bridge funds to that address <span class="tag">server</span></h3>
      <p><span class="tool">build_bridge_transfer</span> constructs the source-chain transactions — an approval where the route escrows collateral, then the transfer. The destination is the address from step 1, even though nothing is deployed there yet.</p>
    </div></div>
    <div class="si you"><div class="n">3</div><div>
      <h3>Sign and send on the source chain <span class="tag">you</span></h3>
      <p>The agent signs with its own key and submits each transaction through <span class="tool">broadcast_transaction</span> with that chain named. Delivery is visible through <span class="tool">get_bridge_status</span>.</p>
    </div></div>
    <div class="si"><div class="n">4</div><div>
      <h3>Act, deploying the account in the same breath <span class="tag">server</span></h3>
      <p><span class="tool">build_transfer</span> or <span class="tool">build_swap</span> with the <code>owner</code> argument builds an operation that creates the account and does the work atomically. Pass <code>gas_token</code> and the bridged token pays the fee, so no ${esc(cfg.identity.nativeSymbol)} is needed at any point.</p>
    </div></div>
  </div>
</section>

` : ""}<section>
  <p class="kicker">Example</p>
  <h2>Sending 10 USDC, fee paid in USDC</h2>
  <p class="intro">A transfer from an account holding no ${esc(cfg.identity.nativeSymbol)} — the paymaster covers the fee in USDC, and the whole thing is one atomic operation.</p>
<pre><code><span class="c">// 1 — ask the server to build it (nothing signed, nothing sent)</span>
<span class="k">build_transfer</span>({
  account:   <span class="k">"0x2b2d…c8d6"</span>,
  token:     <span class="k">"USDC"</span>,
  to:        <span class="k">"0xA399…b64e"</span>,
  amount:    <span class="k">"10"</span>,
  gas_token: <span class="k">"USDC"</span>            <span class="c">// pay the fee in USDC, not ${esc(cfg.identity.nativeSymbol)}</span>
})

<span class="c">// → returns</span>
{
  action:         <span class="k">"TRANSFER"</span>,
  transfer_gate:  [{ result: <span class="k">"APPROVED"</span>, ok: true }],
  gas_payment:    <span class="k">"0.026 USDC (via Unified Token Paymaster)"</span>,
  user_operation: { sender: …, nonce: …, signature: <span class="w">"0x"</span> },
  sign_hash:      <span class="w">"0xafa1…ec37"</span>,
  signing_scheme: <span class="k">"EIP-191 personal_sign over sign_hash by the account owner key"</span>
}

<span class="c">// 2 — sign it yourself. The server is not involved.</span>
<span class="w">const</span> signature = <span class="w">await</span> owner.signMessage({ message: { raw: sign_hash } })

<span class="c">// 3 — hand it back to be delivered</span>
<span class="k">broadcast_user_operation</span>({ user_operation, signature })
<span class="c">// → { user_op_hash: "0x9d1f…67ec", status: "confirmed" }</span>
</code></pre>
</section>

<section>
  <p class="kicker">Example</p>
  <h2>Sending 10 USDC, fee paid in USDC</h2>
  <p class="intro">A transfer from an account holding no ${esc(cfg.identity.nativeSymbol)} — the paymaster covers the fee in USDC, and the whole thing is one atomic operation.</p>
<pre><code><span class="c">// 1 — ask the server to build it (nothing signed, nothing sent)</span>
<span class="k">build_transfer</span>({
  account:   <span class="k">"0x2b2d…c8d6"</span>,
  token:     <span class="k">"USDC"</span>,
  to:        <span class="k">"0xA399…b64e"</span>,
  amount:    <span class="k">"10"</span>,
  gas_token: <span class="k">"USDC"</span>            <span class="c">// pay the fee in USDC, not ${esc(cfg.identity.nativeSymbol)}</span>
})

<span class="c">// → returns</span>
{
  action:         <span class="k">"TRANSFER"</span>,
  transfer_gate:  [{ result: <span class="k">"APPROVED"</span>, ok: true }],
  gas_payment:    <span class="k">"0.026 USDC (via Unified Token Paymaster)"</span>,
  user_operation: { sender: …, nonce: …, signature: <span class="w">"0x"</span> },
  sign_hash:      <span class="w">"0xafa1…ec37"</span>,
  signing_scheme: <span class="k">"EIP-191 personal_sign over sign_hash by the account owner key"</span>
}

<span class="c">// 2 — sign it with the owner key. The server is not involved.</span>
<span class="w">const</span> signature = <span class="w">await</span> owner.signMessage({ message: { raw: sign_hash } })

<span class="c">// 3 — hand it back to be delivered</span>
<span class="k">broadcast_user_operation</span>({ user_operation, signature })
<span class="c">// → { user_op_hash: "0x9d1f…67ec", status: "confirmed" }</span>
</code></pre>
</section>

<section id="tools" class="reference">
  <p class="kicker">Tool reference</p>
  <h2>${chainTools.length} chain tools.</h2>
  <p class="intro">Expand a tool to see its description and arguments. Optional arguments are labeled. Token arguments accept a symbol (<code>USDC</code>), a contract address, or <code>${esc(cfg.identity.nativeSymbol)}</code> for the native coin.</p>
  ${toolHtml}
  <aside class="local-tools"><h3>Five wallet tools.</h3><p>These tools operate on the wallet on this computer and are available only in the local server.</p><p><code>create_agent_wallet</code> · <code>get_agent_wallet</code> · <code>send_transfer</code> · <code>send_swap</code> · <code>get_agent_operation</code></p><a href="#setup">Install and set up →</a></aside>
</section>

${cfg.manifest.bridge.enabled ? `<section>
  <p class="kicker">Bridge</p>
  <h2>What moves, and where</h2>
  <p class="intro">The official Incentiv Bridge, over Hyperlane warp routes, connecting ${esc(chainNames.join(", "))}. Interchain fees are quoted live by <code>get_bridge_routes</code>.</p>
  <div class="tscroll"><table>
    <thead><tr><th>Token</th><th>Chains</th><th class="mono">Approval to bridge in?</th><th>Notes</th></tr></thead>
    <tbody>${routeRows}
    </tbody>
  </table></div>
  ${cfg.manifest.bridge.note ? `<p class="muted">${esc(cfg.manifest.bridge.note)}</p>` : ""}
  <div class="note warm"><b>Bridging in costs source-chain gas; bridging out costs ${esc(cfg.identity.nativeSymbol)}.</b> Sending assets to Incentiv needs a fraction of a cent of ETH or BNB. Sending them back attaches the interchain fee as value on the call — which a paymaster cannot sponsor, only the transaction fee — so the account must hold that ${esc(cfg.identity.nativeSymbol)} outright.</div>
</section>

` : ""}<section>
  <p class="kicker">Behaviour</p>
  <h2>Details the tools handle for you</h2>
  <div class="two">
    <div class="panel"><h3>Accounts appear before they exist</h3><p>An account is created by its first signed operation. Until then the address is real and can hold funds while showing no code — which is what makes funding it ahead of deployment work.</p></div>
    <div class="panel"><h3>The signer is an ordinary key</h3><p>Accounts are controlled by a standard EOA key, so an agent can hold and use it like any other Ethereum key. Passkeys are not used.</p></div>
    <div class="panel"><h3>Fees payable in any supported token</h3><p>Pass <code>gas_token</code> and the operation is built the way the Unified Token Paymaster requires, priced through the on-chain quoter with the paymaster's own validation maths.</p></div>
    <div class="panel"><h3>Compliance is surfaced before signing</h3><p>Every call in a built batch runs through the on-chain TransferGate, so a transfer that would be escrowed or blocked is reported while it is still free to abandon.</p></div>
    <div class="panel"><h3>Balances are read on-chain</h3><p>The explorer only tells the server which tokens an address holds. Every number comes from a live contract call, so a lagging index cannot produce a wrong balance.</p></div>
    <div class="panel"><h3>Swaps route themselves</h3><p>All pools pair against wrapped ${esc(cfg.identity.nativeSymbol)}, so swaps route through it automatically, wrap and unwrap the native coin on either side, and enforce your slippage.</p></div>
  </div>
</section>

<section>
  <p class="kicker">Sources &amp; limits</p>
  <h2>Where the data comes from</h2>
  <p class="intro">Three Incentiv services, and no others.</p>
<pre><code>RPC        ${esc(publicServiceUrl(cfg.endpoints.rpcUrls[0]))}        <span class="c">live state, contract reads, gas</span>
bundler    ${esc(publicServiceUrl(cfg.endpoints.bundlerUrl))}    <span class="c">ERC-4337 estimation and submission</span>
explorer   ${esc(publicServiceUrl(cfg.endpoints.explorerApiUrl))} <span class="c">indexed history and user operations</span></code></pre>
  <h3 style="margin-top:26px">What it deliberately does not do</h3>
  <ul>
    <li><b>It never signs with your keys.</b> The wallet signs only under its authenticated policy, and only on this computer.</li>
    <li><b>Building for an undeployed account needs its owner.</b> Pass <code>owner</code> and the operation deploys the account as it runs; without it the tools will not guess who controls an address.</li>
    <li><b>No NFT tools.</b> NFT balances appear as raw amounts; there are no dedicated NFT read or transfer tools.</li>
    ${cfg.manifest.bridge.enabled && cfg.manifest.bridge.note ? `<li>${esc(cfg.manifest.bridge.note)}</li>` : ""}
    <li><b>USD prices are sparse.</b> The explorer reports no exchange rates for most tokens, so portfolio totals are omitted rather than shown as a misleading zero.</li>
  </ul>
</section>

${troubleshootingHtml()}
</main>
<footer><p>Incentiv MCP · Chain ${cfg.identity.chainId}</p><p><a href="https://incentiv.io/">Incentiv ↗</a> &nbsp; <a href="https://github.com/IncentivNetwork/incentiv-mcp">GitHub ↗</a></p></footer>
<div id="copy-status" class="copy-status" role="status" aria-live="polite"></div>

</div>
<script>${onboardingScript}</script>
</body>
</html>`;
}
