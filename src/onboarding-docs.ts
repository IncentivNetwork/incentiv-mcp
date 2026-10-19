const escape = (value: string) => value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
export const copyBlock = (text: string, label = "command") => `<div class="copy-block"><pre><code>${escape(text)}</code></pre><button type="button" class="copy-command" aria-label="Copy ${escape(label)}" hidden>Copy</button></div>`;

const clients = (mode: string, content: string) => `<div class="client-guide" data-guide="${mode}">
  <div class="client-picker" hidden><label for="${mode}-client">Your AI app</label><select id="${mode}-client"><option value="codex">Codex</option><option value="claude">Claude Desktop</option><option value="cursor">Cursor</option><option value="manual">Another MCP client</option></select></div>
  ${content}</div>`;

/** All instructions are present without JavaScript; the selector progressively filters them. */
export function onboardingHtml(localTools: number): string {
  return `<section id="setup" class="setup-section" aria-labelledby="setup-title">
  <div class="section-heading"><p class="kicker">Install</p><h2 id="setup-title">A wallet on your computer.</h2><p>Chain tools, plus transfers and swaps within the permissions you set. Keys never leave this computer.</p></div>
  <div class="instructions">
  <h3>1. Install Node.js and the package</h3>
  <p>Install Node.js 22.18 or newer. Use PowerShell on Windows or a terminal on macOS/Linux. OS credential storage must be unlocked; Linux requires Secret Service.</p>
  ${copyBlock("npm install --global --ignore-scripts incentiv-mcp\nincentiv-mcp setup", "installation commands")}
  <p>Setup connects the absolute path of the installed executable. For a source checkout, run <code>npm ci --ignore-scripts</code>, <code>npm run build</code> and <code>node --use-system-ca dist/index.js setup</code> instead, and use <code>node --use-system-ca dist/index.js</code> in place of <code>incentiv-mcp</code> in the commands below.</p>
  <h3>2. Set permissions in your own terminal</h3>
  <p>Choose your app, assets and recipients. Set transfer/swap limits, daily budgets including gas, maximum holdings and gas allowances. Review the displayed RPC trust if you enable swaps.</p>
  <p>Save an administration password and a separate backup recovery password. Enter both only in the hidden terminal prompts. Setup verifies an encrypted backup before you type <code>ENABLE</code>. There is no administration-password reset.</p>
  <p><strong>Setup never sends funds.</strong> If interrupted, rerun it to continue with the same wallet.</p>
  <h3>3. Reconnect your AI app</h3>
  ${clients("local", `
    <div data-client="codex"><h4>Codex</h4><p>Choose Codex in setup. It uses the Codex CLI and preserves other connections. If the CLI is unavailable, copy the generated TOML into your Codex configuration. Restart the app or reconnect MCP.</p></div>
    <div data-client="claude"><h4>Claude Desktop</h4><p>Choose Claude Desktop in setup on Windows or macOS. It adds the local server to your desktop configuration and preserves other settings. Fully quit and reopen the app. A remote Claude connector cannot reach this wallet.</p></div>
    <div data-client="cursor"><h4>Cursor</h4><p>Choose Cursor in setup. It updates your personal MCP configuration while preserving existing servers. Restart Cursor and check that the Incentiv wallet server is enabled.</p></div>
    <div data-client="manual"><h4>Another MCP client</h4><p>Choose manual in setup. Copy the generated command, arguments and environment into your client’s local stdio MCP configuration. Keep the displayed absolute paths and wallet profile.</p></div>
  `)}
  <h3>4. Verify your wallet</h3>
  ${copyBlock("Show the Incentiv network status, then show my Incentiv wallet balance.", "local connection prompt")}
  <p>Expect the configured network and the same wallet address shown by setup. The server exposes ${localTools} tools for this network configuration.</p>
  <details><summary>Fund your wallet and make a first transaction</summary>
    <p>Verify the smart-account address and network before funding. Stay within your holdings limits and keep enough permitted gas tokens. Ask for a fresh estimate: the first operation includes account deployment. Your wallet can receive funds before deployment; EntryPoint gas deposits are separate from transferable CENT.</p>
    <p>Replace AMOUNT and RECIPIENT below. These prompts authorize real transactions within your configured permissions.</p>
    ${copyBlock("Send AMOUNT USDC to RECIPIENT from my Incentiv wallet, using a new request ID. Check its status and show the transaction link.", "transfer prompt")}
    ${copyBlock("Quote a swap of AMOUNT USDC to CENT. Show minimum output and gas, then swap within my configured limits using a new request ID. Check its status.", "swap prompt")}
    <p>Add “pay gas in USDC” if your policy permits it. Both swap assets need allowances. Your app may request its own confirmation. For a pending operation, check its existing request ID; never use a new ID to retry an uncertain send.</p>
  </details>
  <details><summary>Stop signing, back up or restore</summary>
    ${copyBlock("incentiv-mcp wallet disable", "disable signing command")}
    <p>Stops new signing and rebroadcast; already-submitted transactions cannot be revoked. Rerun setup to reconnect or review permissions.</p>
    ${copyBlock("incentiv-mcp wallet backup --out /absolute/path/to/new-backup.json\nincentiv-mcp wallet restore --in /absolute/path/to/backup.json", "backup and restore commands")}
    <p>Use a full drive path on Windows and quote paths containing spaces. Keep the backup away from this computer and passwords separately. Restore into an empty profile and disable other copies before re-enabling. Never delete a wallet to force setup.</p>
    ${copyBlock("incentiv-mcp --wallet-profile second setup", "separate profile command")}
    <p>Only use a second profile when intentionally creating a separate wallet. Use the same profile on every administration command.</p>
  </details>
  </div></section>`;
}

export function troubleshootingHtml(): string {
  return `<section id="troubleshooting" class="setup-section"><div class="section-heading"><p class="kicker">Troubleshooting</p><h2>A clear next step.</h2></div><div class="instructions">
  <details><summary>Command not recognized</summary><p>Open a new terminal after installation and check <code>node --version</code>. For a source checkout, run <code>node --use-system-ca dist/index.js</code> in place of <code>incentiv-mcp</code>.</p></details>
  <details><summary>Network, certificates or credentials</summary><p>Run <code>incentiv-mcp wallet doctor</code>. Unlock your OS credential session; Linux needs Secret Service. Use Node’s <code>--use-system-ca</code> option for system certificates. Keep certificate verification enabled. Investigate identity mismatches; never bypass them.</p></details>
  <details><summary>Setup stopped or the app is not connected</summary><p>Keep wallet files and rerun setup. Use a new backup filename in an existing directory. Restart your app, inspect MCP logs and check the generated absolute paths. Setup preserves malformed configurations and prints a manual alternative.</p></details>
  <details><summary>Policy denied or operation pending</summary><p>Review gas quotes and balances before changing limits locally through setup. Check pending operations with their original request IDs. Preserve wallet files if authenticated recovery is required.</p></details>
  <p class="small">More detail: <a href="https://github.com/IncentivNetwork/incentiv-mcp/blob/main/docs/wallet-storage.md">Wallet storage and recovery ↗</a></p>
  </div></section>`;
}

export const onboardingScript = `
for (const guide of document.querySelectorAll('.client-guide')) {
  const picker = guide.querySelector('select');
  const update = () => { for (const panel of guide.querySelectorAll('[data-client]')) panel.hidden = panel.dataset.client !== picker.value; };
  picker.addEventListener('change', update);
  guide.querySelector('.client-picker').hidden = false;
  update();
}
for (const button of document.querySelectorAll('.copy-command')) {
  button.hidden = false;
  button.addEventListener('click', async () => {
    const code = button.parentElement.querySelector('code');
    const status = document.getElementById('copy-status');
    try {
      await navigator.clipboard.writeText(code.textContent);
      button.textContent = 'Copied'; status.textContent = 'Copied to clipboard.';
      setTimeout(() => { button.textContent = 'Copy'; }, 1800);
    } catch {
      const range = document.createRange(); range.selectNodeContents(code);
      const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
      status.textContent = 'Text selected. Press Ctrl+C or Command+C to copy.';
    }
  });
}`;
