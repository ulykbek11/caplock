#!/usr/bin/env node
import { appendFileSync } from "node:fs";
import path from "node:path";
import { readLockfile, findLock } from "./lockfile.js";
import { readConfig } from "./config.js";
import { identifyPackage, lifecycleFromEnv } from "./package.js";
import { defaultPolicy } from "./policy.js";
import { selectSandboxBackend } from "./sandbox/backend.js";
import type { LockEntry } from "./types.js";

async function main(): Promise<void> {
  const args = process.argv.slice(2); const at = args.indexOf("-c"); const command = at >= 0 ? args[at + 1] : undefined;
  if (!command) { console.error("caplock-shell expects: -c <command>"); process.exitCode = 2; return; }
  // The canary is a locally-created harmless package.  It verifies npm actually
  // invokes this executable before any real lifecycle command is considered.
  if (process.env.CAPLOCK_CANARY_MARKER) {
    appendFileSync(process.env.CAPLOCK_CANARY_MARKER, "CAPLOCK_INTERCEPTED\n");
    const child = await import("node:child_process");
    const result = child.spawnSync(process.platform === "win32" ? "cmd.exe" : "/bin/sh", process.platform === "win32" ? ["/d", "/s", "/c", command] : ["-c", command], { stdio: "inherit" });
    process.exitCode = result.status ?? 1;
    return;
  }
  const root = process.env.CAPLOCK_PROJECT_ROOT ? path.resolve(process.env.CAPLOCK_PROJECT_ROOT) : process.cwd();
  const identity = identifyPackage(process.cwd(), root); const lifecycle = lifecycleFromEnv(process.env);
  if (!lifecycle) { console.error("CapLock refused an unrecognized lifecycle invocation."); process.exitCode = 1; return; }
  const nodeModules = path.join(root, "node_modules");
  if (!identity.packageDir.startsWith(`${nodeModules}${path.sep}`)) { console.error("CapLock refuses root-project lifecycle scripts through the dependency sandbox shim."); process.exitCode = 1; return; }
  const candidate: LockEntry = { package: { name: identity.name, version: identity.version, integrity: identity.integrity }, lifecycle, policy: defaultPolicy() };
  const approved = findLock(readLockfile(root), candidate);
  if (!approved || approved.lifecycle.hash !== lifecycle.hash) { console.error(`CapLock requires review: ${identity.name}@${identity.version} ${lifecycle.event} is not approved or its command changed.`); process.exitCode = 1; return; }
  const shell = process.platform === "win32" ? (process.env.ComSpec ?? path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "cmd.exe")) : "/bin/sh";
  const shellArgs = process.platform === "win32" ? ["/d", "/s", "/c", command] : ["-c", command];
  const result = await selectSandboxBackend().run({ executable: shell, args: shellArgs }, approved.policy, { projectRoot: root, identity, traceFile: process.env.CAPLOCK_TRACE_FILE, timeoutMs: readConfig(root).execution.timeoutSeconds * 1000 });
  process.exitCode = result.code;
}
main().catch((error: unknown) => { console.error(process.env.CAPLOCK_DEBUG ? error : `CapLock shell failed: ${error instanceof Error ? error.message : String(error)}`); process.exitCode = 1; });
