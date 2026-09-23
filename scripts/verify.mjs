import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const cwd = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
for (const script of ["lint", "typecheck", "test", "build"]) {
  const result = process.platform === "win32"
    ? spawnSync("cmd.exe", ["/d", "/s", "/c", `npm.cmd run ${script}`], { cwd, stdio: "inherit" })
    : spawnSync("npm", ["run", script], { cwd, stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
