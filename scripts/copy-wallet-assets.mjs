import { copyFile } from "node:fs/promises";

await copyFile(new URL("../src/wallet/windows-permissions.ps1", import.meta.url),
  new URL("../dist/wallet/windows-permissions.ps1", import.meta.url));
