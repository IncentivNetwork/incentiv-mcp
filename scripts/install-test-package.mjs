import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

export async function installTestPackage(root, directory) {
  const npm = process.env.npm_execpath;
  if (!npm) throw new Error("Run this script through npm");
  const [packed] = JSON.parse(execFileSync(process.execPath, [
    npm, "pack", "--ignore-scripts", "--json", "--pack-destination", directory,
  ], { cwd: root, encoding: "utf8" }));
  const archive = join(directory, packed.filename);
  execFileSync(process.execPath, [
    npm, "install", "--prefix", directory, "--ignore-scripts", "--no-audit", "--no-fund", "--prefer-offline",
    "--no-package-lock", "--omit=dev", archive,
  ], { stdio: ["ignore", "ignore", "inherit"] });
  return {
    dist: join(directory, "node_modules", packed.name, "dist"),
    tarballSha256: createHash("sha256").update(await readFile(archive)).digest("hex"),
  };
}
