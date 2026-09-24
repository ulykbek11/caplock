import { rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

rmSync("dist", { recursive: true, force: true });
const result = spawnSync(process.execPath, ["node_modules/typescript/bin/tsc", "-p", "tsconfig.build.json"], { stdio: "inherit", shell: false });
if (result.status === 0 && process.platform === "win32") writeFileSync("dist/shell.cmd", "@echo off\r\nnode \"%~dp0shell.js\" %*\r\n", "utf8");
process.exit(result.status ?? 1);
