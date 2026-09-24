import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
function invoke(name) {
  const child = process.platform === "win32"
    ? spawnSync("cmd.exe", ["/d", "/s", "/c", `npm.cmd run ${name}`], { cwd: root, stdio: "inherit", shell: false })
    : spawnSync("npm", ["run", name], { cwd: root, stdio: "inherit", shell: false });
  if (child.error || child.status !== 0) process.exit(child.status ?? 1);
}
invoke("build");
invoke("typecheck");
if (process.platform === "win32") invoke("native:build");
