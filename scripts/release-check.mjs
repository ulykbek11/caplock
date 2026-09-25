import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { checkDoctor, parsePackJson } from "./release-check-doctor.mjs";
import { smokePackedCli } from "./packed-smoke.mjs";

const npm = process.platform === "win32" ? "cmd.exe" : "npm";
const platformScript = process.platform === "win32" ? "verify:windows" : process.platform === "linux" ? "verify:linux" : process.platform === "darwin" ? "verify:macos" : undefined;
const packageMetadata = JSON.parse(readFileSync(path.join(process.cwd(), "package.json"), "utf8"));

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
  const smoke = smokePackedCli({ consumerRoot: temporary, packageName: packageMetadata.name, expectedVersion: packageMetadata.version });
  console.log(`Packed CLI smoke passed: ${smoke.cli}`);
} finally { rmSync(temporary, { recursive: true, force: true }); }
