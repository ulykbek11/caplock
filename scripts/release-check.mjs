import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { checkDoctor, parsePackJson } from "./release-check-doctor.mjs";

const npm = process.platform === "win32" ? "cmd.exe" : "npm";
const platformScript = process.platform === "win32" ? "verify:windows" : process.platform === "linux" ? "verify:linux" : process.platform === "darwin" ? "verify:macos" : undefined;

function invoke(args, options = {}) { const invocation = process.platform === "win32" ? ["/d", "/s", "/c", ["npm.cmd", ...args].join(" ")] : args; const result = spawnSync(npm, invocation, { stdio: options.stdio ?? "inherit", encoding: "utf8", shell: false, ...options }); if (result.error || result.status !== 0) process.exit(result.status ?? 1); return result; }
const temporary = mkdtempSync(path.join(os.tmpdir(), "caplock-release-check-"));
try {
  invoke(["run", "verify"]);
  if (platformScript) invoke(["run", platformScript]);
  checkDoctor({ root: process.cwd() });
  // Run the freshness hook separately so its compiler/native-build output
  // cannot contaminate npm's machine-readable pack JSON.
  invoke(["run", "prepack"]);
  invoke(["pack", "--dry-run", "--ignore-scripts", "--pack-destination", temporary, "--cache", path.join(temporary, "cache")]);
  const packed = invoke(["pack", "--json", "--ignore-scripts", "--pack-destination", temporary, "--cache", path.join(temporary, "cache")], { stdio: "pipe" });
  const tarball = path.join(temporary, parsePackJson(packed.stdout).filename);
  invoke(["install", "--ignore-scripts", "--no-package-lock", "--prefix", temporary, tarball, "--cache", path.join(temporary, "cache")]);
  const cli = path.join(temporary, "node_modules", ".bin", process.platform === "win32" ? "caplock.cmd" : "caplock");
  const smoke = process.platform === "win32" ? spawnSync("cmd.exe", ["/d", "/s", "/c", `${cli} version`], { stdio: "inherit", shell: false }) : spawnSync(cli, ["version"], { stdio: "inherit", shell: false }); if (smoke.status !== 0) process.exit(smoke.status ?? 1);
} finally { rmSync(temporary, { recursive: true, force: true }); }
