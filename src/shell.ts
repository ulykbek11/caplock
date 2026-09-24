#!/usr/bin/env node
import { appendFileSync } from "node:fs";
import path from "node:path";
import { readLockfile, findLock } from "./lockfile.js";
import { readConfig } from "./config.js";
import { identifyPackage, isExternalInstalledPackage, lifecycleFromEnv, lifecycleFromPackage, samePackageRoot } from "./package.js";
import { defaultPolicy, validatePolicy } from "./policy.js";
import { preflightSandbox, selectSandboxBackend } from "./sandbox/backend.js";
import type { LockEntry } from "./types.js";
import { redactText } from "./util.js";

let failureStage = "shell.start";
function stage(name: string): void {
  failureStage = name;
  if (process.env.CAPLOCK_DEBUG === "1") console.error(`CapLock stage: ${name}`);
}

async function main(): Promise<void> {
  stage("shell.start");
  const args = process.argv.slice(2); const at = args.indexOf("-c"); const invocationCommand = at >= 0 ? args[at + 1] : undefined;
  if (!invocationCommand) { console.error("caplock-shell expects: -c <command>"); process.exitCode = 2; return; }
  // The canary is a locally-created harmless package.  It verifies npm actually
  // invokes this executable before any real lifecycle command is considered.
  if (process.env.CAPLOCK_CANARY_MARKER) {
    appendFileSync(process.env.CAPLOCK_CANARY_MARKER, "CAPLOCK_INTERCEPTED\n");
    const child = await import("node:child_process");
    const result = child.spawnSync(process.platform === "win32" ? "cmd.exe" : "/bin/sh", process.platform === "win32" ? ["/d", "/s", "/c", invocationCommand] : ["-c", invocationCommand], { stdio: "inherit" });
    process.exitCode = result.status ?? 1;
    return;
  }
  const root = process.env.CAPLOCK_PROJECT_ROOT ? path.resolve(process.env.CAPLOCK_PROJECT_ROOT) : process.cwd();
  stage("shell.project-resolved");
  const cwdIdentity = identifyPackage(process.cwd(), root);
  const metadataManifest = process.env.npm_package_json;
  const metadataIdentity = metadataManifest && path.isAbsolute(metadataManifest) ? identifyPackage(path.dirname(metadataManifest), root) : undefined;
  // npm 11 may forward the parent npm metadata to a custom script-shell. Do
  // not let that unrelated root identity influence approval; only accept it
  // when it describes the package whose lifecycle is being launched.
  const identity = metadataIdentity && metadataIdentity.name === cwdIdentity.name && metadataIdentity.version === cwdIdentity.version && samePackageRoot(metadataIdentity, cwdIdentity) ? metadataIdentity : cwdIdentity;
  stage("shell.package-identified");
  const fromEnv = lifecycleFromEnv(process.env);
  const metadataCommand = process.env.npm_lifecycle_script;
  if (process.env.CAPLOCK_DEBUG) console.error(`CapLock metadata: event=${process.env.npm_lifecycle_event ?? "<none>"}; script=${redactText(metadataCommand ?? "<none>")}; packageJson=${metadataManifest ?? "<none>"}; metadataMatchesCwd=${metadataIdentity ? samePackageRoot(metadataIdentity, cwdIdentity) : false}`);
  const lifecycle = fromEnv && metadataIdentity && samePackageRoot(metadataIdentity, cwdIdentity) ? fromEnv : lifecycleFromPackage(identity.packageDir, invocationCommand);
  stage("shell.lifecycle-event-resolved");
  if (!lifecycle) { console.error("CapLock blocked lifecycle: policy validation failed (unrecognized lifecycle invocation)"); process.exitCode = 1; return; }
  stage("shell.command-resolved");
  if (!isExternalInstalledPackage(identity, root)) { console.error("CapLock blocked lifecycle: package root is outside node_modules"); process.exitCode = 1; return; }
  const candidate: LockEntry = { package: { name: identity.name, version: identity.version, integrity: identity.integrity }, lifecycle, policy: defaultPolicy() };
  const lockfile = readLockfile(root);
  stage("shell.lockfile-loaded");
  const approved = findLock(lockfile, candidate);
  if (!approved) { console.error("CapLock blocked lifecycle: package not present in lockfile"); process.exitCode = 1; return; }
  if (approved.lifecycle.hash !== lifecycle.hash) { console.error("CapLock blocked lifecycle: command hash mismatch"); process.exitCode = 1; return; }
  stage("shell.lock-entry-matched");
  const shell = process.platform === "win32" ? (process.env.ComSpec ?? path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "cmd.exe")) : "/bin/sh";
  const command = lifecycle.command;
  const shellArgs = process.platform === "win32" ? ["/d", "/s", "/c", command] : ["-c", command];
  // The lockfile is user-editable input. Validate it in the trusted parent on
  // every invocation, before any lifecycle command reaches a backend.
  const policy = validatePolicy(approved.policy, root, identity.packageDir);
  stage("shell.policy-validated");
  stage("shell.backend-selected");
  const backend = selectSandboxBackend();
  stage("shell.preflight-start");
  await preflightSandbox(policy);
  stage("shell.preflight-pass");
  stage("shell.environment-built");
  stage("shell.sandbox-start");
  const result = await backend.run({ executable: shell, args: shellArgs }, policy, { projectRoot: root, identity, controlEnv: process.env, childEnv: process.env, traceFile: process.env.CAPLOCK_TRACE_FILE, timeoutMs: readConfig(root).execution.timeoutSeconds * 1000 });
  stage("shell.sandbox-exit");
  // The native helper is intentionally captured so CapLock can classify its
  // result, but lifecycle output must still reach npm/the debug harness.
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.code !== 0 && process.env.CAPLOCK_DEBUG === "1") console.error(`CapLock sandbox child failed: stage=lifecycle exitCode=${result.code}`);
  process.exitCode = result.code;
}
main().catch((error: unknown) => { const reason = error instanceof Error ? error.message : String(error); if (process.env.CAPLOCK_DEBUG === "1") { console.error(`CapLock failure stage: ${failureStage}`); console.error(`CapLock failure reason: ${redactText(reason)}`); } console.error(`CapLock blocked lifecycle: ${redactText(reason)}`); process.exitCode = 1; });
