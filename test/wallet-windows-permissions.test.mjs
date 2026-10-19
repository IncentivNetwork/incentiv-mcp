import assert from "node:assert/strict";
import test from "node:test";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFile = promisify(childProcess.execFile);

test("Windows helper reuses its process, rechecks ACLs, correlates replies and fails closed on death/timeout", { skip: process.platform !== "win32", timeout: 60_000 }, async t => {
  const children = [], originalSpawn = childProcess.spawn;
  childProcess.spawn = (...args) => {
    const child = originalSpawn(...args);
    if (args[1]?.some(arg => String(arg).endsWith("windows-permissions.ps1"))) children.push(child);
    return child;
  };
  syncBuiltinESMExports();
  t.after(() => { childProcess.spawn = originalSpawn; syncBuiltinESMExports(); });
  const { privateDirectory, verifyPaths, writeNew } = await import("../src/wallet/files.ts");
  const parent = await mkdtemp(join(await realpath(tmpdir()), "incentiv-permissions-test-"));
  // Only this mkdtemp-created test directory is removed; no real wallet is opened.
  t.after(() => rm(parent, { recursive: true, force: true }));
  const root = join(parent, "private"), good = join(root, "spaces and Unicode \u05e9\u05dc\u05d5\u05dd.json"), bad = join(root, "changed permissions.json");
  await privateDirectory(root);
  await writeNew(good, "{}"); await writeNew(bad, "{}");
  for (let i = 0; i < 20; i++) await verifyPaths([root, good, bad]);
  assert.equal(children.length, 1, "checks must reuse the helper");

  // Add a non-owner ACE after a successful verification. Every later check must reject it.
  const change = execFile(join(process.env.SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), ["-NoProfile", "-NonInteractive", "-Command", `
    $ErrorActionPreference = 'Stop'
    $path = [Console]::In.ReadToEnd()
    $acl = [IO.File]::GetAccessControl($path)
    $everyone = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($everyone, 'Read', 'Allow')))
    [IO.File]::SetAccessControl($path, $acl)
  `]);
  change.child.stdin.end(bad); await change;
  const checks = await Promise.allSettled([verifyPaths([good]), verifyPaths([bad]), verifyPaths([good])]);
  assert.deepEqual(checks.map(check => check.status), ["fulfilled", "rejected", "fulfilled"]);
  assert.equal(checks[1].reason.code, "wallet_permissions_invalid");
  assert.ok(!checks[1].reason.message.includes(bad));
  assert.equal(children.length, 1, "a rejected ACL must not corrupt the next response");

  // Hold a request in the pipe, then kill its helper. It cannot return an old success.
  const child = children[0]; child.stdin.cork();
  let written;
  const requestWritten = new Promise(resolve => { written = resolve; });
  const originalWrite = child.stdin.write;
  child.stdin.write = function (...args) { const result = originalWrite.apply(this, args); written(); return result; };
  const killed = assert.rejects(verifyPaths([good]), { code: "wallet_permissions_invalid" });
  await requestWritten; child.kill(); await killed;
  await verifyPaths([good]);
  assert.equal(children.length, 2, "the next operation can start a fresh helper");

  // A silent helper times out every outstanding request, rather than approving any.
  children[1].stdin.cork();
  await Promise.all([1, 2, 3].map(() => assert.rejects(verifyPaths([good]), { code: "wallet_permissions_invalid" })));
  await verifyPaths([good]);
  assert.equal(children.length, 3);

  for (const reply of ['SECRET_ERROR_CANARY\n', '{"ok":true}\n', 'x'.repeat(4097)]) {
    const active = children.at(-1); active.stdin.cork();
    const write = active.stdin.write.bind(active.stdin);
    active.stdin.write = (...args) => {
      const result = write(...args);
      queueMicrotask(() => active.stdout.emit("data", reply));
      return result;
    };
    await assert.rejects(verifyPaths([good]), error => error.code === "wallet_permissions_invalid" && !error.message.includes("SECRET_ERROR_CANARY"));
    await verifyPaths([good]);
  }
});

test("an idle Windows permission helper does not keep a CLI process alive", { skip: process.platform !== "win32" }, async () => {
  const url = new URL("../src/wallet/files.ts", import.meta.url).href;
  const result = await execFile(process.execPath, ["--import", "tsx", "--input-type=module", "-e",
    `const { hostIdentity } = await import(${JSON.stringify(url)}); await hostIdentity();`,
  ], { timeout: 10_000, windowsHide: true });
  assert.equal(result.stdout, ""); assert.equal(result.stderr, "");
});
