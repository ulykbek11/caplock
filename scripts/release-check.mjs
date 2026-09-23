import { spawnSync } from "node:child_process";

const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const platformScript = process.platform === "win32" ? "verify:windows" : process.platform === "linux" ? "verify:linux" : process.platform === "darwin" ? "verify:macos" : undefined;

for (const args of [["run", "verify"], ...(platformScript ? [["run", platformScript]] : []), ["pack", "--dry-run"]]) {
  const result = spawnSync(npm, args, { stdio: "inherit", shell: false });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
