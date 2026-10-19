import assert from "node:assert/strict";
import test from "node:test";
import vm from "node:vm";
import { MAINNET } from "../src/config.ts";
import { Ctx } from "../src/context.ts";
import { makeServer } from "../src/server.ts";
import { renderHtml, renderMarkdown } from "../src/docs.ts";
import { onboardingScript } from "../src/onboarding-docs.ts";

test("documentation leads with local install and keeps the tool catalog accurate", async () => {
  for (const bridge of [true, false]) {
    const config = structuredClone(MAINNET);
    config.manifest.bridge.enabled = bridge;
    const bundle = makeServer(new Ctx(config), () => []);
    try {
      const html = renderHtml(config, bundle.catalog);
      const count = bridge ? 24 : 20;
      assert.match(html, new RegExp(`${count} chain tools`));
      assert.match(html, new RegExp(`The server exposes ${count + 5} tools`));
      assert.equal((html.match(/class="tool-entry"/g) ?? []).length, count);
      for (const id of ["setup", "troubleshooting", "tools"]) assert.equal((html.match(new RegExp(`id="${id}"`, "g")) ?? []).length, 1);
      assert.ok(html.indexOf('id="setup"') < html.indexOf('id="tools"'));
      assert.match(html, /npm install --global --ignore-scripts incentiv-mcp/);
      assert.match(html, /Five wallet tools/);
      assert.doesNotMatch(html, /<script[^>]+src=|<link[^>]+stylesheet/);
      assert.match(html, /data:font\/woff2;base64/);
      assert.equal((html.match(/<details[ >]/g) ?? []).length, (html.match(/<\/details>/g) ?? []).length);
      if (!bridge) assert.doesNotMatch(html, /build_bridge_transfer|get_bridge_routes|Solana/);
      const md = renderMarkdown(config, bundle.catalog);
      assert.ok(md.indexOf("## Install") < md.indexOf("## Tools"));
      assert.match(md, /npm install --global --ignore-scripts incentiv-mcp/);
      assert.doesNotMatch(md, /send_transfer|create_agent_wallet/);
    } finally { await bundle.server.close(); }
  }
});

test("HTML escapes endpoints and catalog content, and exposes instructions without JavaScript", () => {
  const hostile = '</code><script>alert("x")</script>&';
  const html = renderHtml(MAINNET, [{ name: hostile, description: hostile, readOnly: true, params: [{ name: hostile, required: true }] }]);
  assert.doesNotMatch(html, /<script>alert/);
  assert.match(html, /&lt;script&gt;alert\(&quot;x&quot;\)/);
  // Only the selector is hidden in server-rendered markup; all app guidance is readable.
  assert.equal((html.match(/<div data-client="(?:codex|claude|cursor|manual)">/g) ?? []).length, 4);
  assert.doesNotMatch(html, /data-client="[^"]+" hidden/);
  assert.match(html, /class="client-picker" hidden/);
  assert.match(html, /class="copy-command"[^>]+hidden/);
});

test("client choices stay independent and copy supports denied clipboard access", async () => {
  const makeGuide = () => {
    const panels = ["codex", "claude", "cursor", "manual"].map(client => ({ dataset: { client }, hidden: false }));
    const picker = { value: "codex", addEventListener: (_, fn) => { picker.change = fn; } };
    const wrapper = { hidden: true };
    return { panels, picker, wrapper, querySelector: selector => selector === "select" ? picker : wrapper, querySelectorAll: () => panels };
  };
  const guides = [makeGuide(), makeGuide()];
  const code = { textContent: "https://example.test/mcp" }, status = {};
  const button = { hidden: true, parentElement: { querySelector: () => code }, addEventListener: (_, fn) => { button.click = fn; } };
  let copied, selected, deny = false;
  vm.runInNewContext(onboardingScript, {
    document: {
      querySelectorAll: selector => selector === ".client-guide" ? guides : [button],
      getElementById: () => status,
      createRange: () => ({ selectNodeContents: node => { selected = node; } }),
    },
    navigator: { clipboard: { writeText: async text => { if (deny) throw Error("denied"); copied = text; } } },
    window: { getSelection: () => ({ removeAllRanges() {}, addRange() {} }) },
    setTimeout() {},
  });
  assert.equal(button.hidden, false);
  guides[0].picker.value = "cursor"; guides[0].picker.change();
  assert.equal(guides[0].panels.find(p => !p.hidden).dataset.client, "cursor");
  assert.equal(guides[1].panels.find(p => !p.hidden).dataset.client, "codex");
  await button.click();
  assert.equal(copied, code.textContent);
  assert.equal(status.textContent, "Copied to clipboard.");
  deny = true; await button.click();
  assert.equal(selected, code);
  assert.match(status.textContent, /Ctrl\+C or Command\+C/);
});
