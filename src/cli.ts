#!/usr/bin/env node
import { Command } from "commander";
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import pc from "picocolors";
import { CLI_NAME, EXIT, PACKAGE_NAME, PRODUCT_NAME, STATE_DIR_NAME } from "./constants.js";
import { configPath, readConfig, writeConfig } from "./config.js";
import { doctor } from "./doctor.js";
import { findLock, readLockfile, writeLockfile } from "./lockfile.js";
import { defaultPolicy, validatePolicy } from "./policy.js";
import { commandExists, packageManagerCommand, run } from "./process.js";
import { identifyPackage } from "./package.js";
import type { LockEntry } from "./types.js";

const root = (): string => process.cwd();
function shellPath(): string { return path.join(path.dirname(process.argv[1] ?? ""), "shell.js"); }
function scan(rootDir: string, requested?: string): LockEntry[] { const base = path.join(rootDir, "node_modules"); const entries: LockEntry[] = []; if (!existsSync(base)) return entries; const visit = (dir: string): void => { for (const name of requireDir(dir)) { if (name.startsWith(".")) continue; if (name.startsWith("@")) visit(path.join(dir, name)); else { const packageDir = path.join(dir, name); const file = path.join(packageDir, "package.json"); if (!existsSync(file)) continue; const pkg = JSON.parse(readFileSync(file, "utf8")) as { name?: string; version?: string; scripts?: Record<string, string> }; if (!pkg.name || !pkg.version || (requested && pkg.name !== requested)) continue; const identity = identifyPackage(packageDir, rootDir); for (const event of ["preinstall", "install", "postinstall"] as const) { const command = pkg.scripts?.[event]; if (command) { const policy = defaultPolicy(); if (process.env.CAPLOCK_LEARN_NETWORK === "host") policy.network = "host"; entries.push({ package: { name: pkg.name, version: pkg.version, integrity: identity.integrity }, lifecycle: { event, command, hash: (awaitHash(command)) }, policy }); } } } } }; visit(base); return entries; }
function requireDir(dir: string): string[] { try { return readdirSync(dir); } catch { return []; } }
function awaitHash(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function selectedManager(): "npm" | "pnpm" { const configured = process.env.CAPLOCK_PACKAGE_MANAGER; if (configured === "pnpm" || (!configured && existsSync(path.join(root(), "pnpm-lock.yaml")))) return "pnpm"; return "npm"; }
async function canary(project: string, manager: "npm" | "pnpm"): Promise<boolean> {
  if (!(await commandExists(manager))) return false;
  const temp = path.join(os.tmpdir(), `caplock-canary-${Date.now()}-${randomUUID()}`); const marker = path.join(temp, "marker");
  try {
    mkdirSync(path.join(temp, "node_modules", "canary"), { recursive: true }); writeFileSync(path.join(temp, "package.json"), '{"name":"canary-root","version":"1.0.0"}'); writeFileSync(path.join(temp, "node_modules", "canary", "package.json"), '{"name":"canary","version":"1.0.0","scripts":{"install":"echo canary"}}');
    const result = await run(packageManagerCommand(manager), ["rebuild", "canary", "--foreground-scripts"], { cwd: temp, env: { ...process.env, npm_config_script_shell: shellPath(), CAPLOCK_PROJECT_ROOT: project, CAPLOCK_CANARY_MARKER: marker } }); return result.code === 0 && existsSync(marker);
  } finally { rmSync(temp, { recursive: true, force: true }); }
}

const program = new Command().name(CLI_NAME).description("Sandbox npm install scripts before they touch your machine.").version("0.1.0");
program.option("--debug", "show debug details").option("--json", "emit machine-readable output").option("--quiet", "suppress non-essential output").option("--no-color", "disable terminal colors").option("--yes", "approve an already displayed learn baseline (for non-interactive use)").option("--network <mode>", "learn policy network mode: none or host");
program.hook("preAction", async (_command, actionCommand) => {
  if (actionCommand.name() !== "learn") return;
  const options = actionCommand.optsWithGlobals();
  if (options.network && options.network !== "none" && options.network !== "host") throw new Error("--network must be none or host.");
  if (options.network) process.env.CAPLOCK_LEARN_NETWORK = options.network;
  const requested = actionCommand.args[0] as string | undefined;
  const existing = readLockfile(root());
  const proposed = scan(root(), requested).filter((entry) => !findLock(existing, entry));
  for (const entry of proposed) validatePolicy(entry.policy, root(), path.join(root(), "node_modules", entry.package.name));
  if (proposed.length) console.log(proposed.map((entry) => `${entry.package.name}@${entry.package.version}${entry.package.integrity ? `\n  integrity: ${entry.package.integrity}` : ""}\n  ${entry.lifecycle.event}: ${entry.lifecycle.command}\n  proposed network: ${entry.policy.network}`).join("\n\n"));
  if (options.yes) return;
  if (!process.stdin.isTTY) throw new Error("caplock learn requires explicit --yes when stdin is non-interactive.");
  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  try { if (!/^y(es)?$/i.test((await prompt.question("Save this policy? [y/N] ")).trim())) throw new Error("Baseline was not saved."); }
  finally { prompt.close(); }
});
program.command("doctor").action(async () => { const checks = await doctor(root()); const good = checks.every((c) => c.ok); if (program.opts().json) console.log(JSON.stringify({ product: PRODUCT_NAME, ready: good, checks }, null, 2)); else for (const c of checks) console.log(`${c.ok ? pc.green("✓") : pc.red("✗")} ${c.name}: ${c.detail}`); process.exitCode = good ? EXIT.success : (process.platform === "linux" ? EXIT.failure : EXIT.unsupported); });
program.command("init").description("Create CapLock state without changing package.json").action(() => { const state = path.join(root(), STATE_DIR_NAME); mkdirSync(state, { recursive: true, mode: 0o700 }); writeConfig(root()); writeLockfile(root(), readLockfile(root())); const ignore = path.join(root(), ".gitignore"); const existing = existsSync(ignore) ? readFileSync(ignore, "utf8") : ""; if (!existing.split(/\r?\n/).includes(".caplock/")) appendFileSync(ignore, `${existing && !existing.endsWith("\n") ? "\n" : ""}.caplock/\n`); console.log(`CapLock initialized.\n\nPackage manager: npm\nPolicy: ${configPath(root())}\n\nNext:\n  caplock learn`); });
program.command("learn [package]").description("Review installed lifecycle scripts and record a baseline").action((packageName?: string) => { const lock = readLockfile(root()); const found = scan(root(), packageName); if (packageName && found.length === 0) throw new Error(`No lifecycle scripts found for ${packageName} in node_modules.`); for (const item of found) if (!findLock(lock, item)) lock.packages.push(item); writeLockfile(root(), lock); console.log(pc.green(`✓ Recorded ${found.length} lifecycle script(s) in .caplock/caplock.lock`)); });
program.command("install [managerArgs...]").allowUnknownOption(true).description("Install dependencies, then run approved lifecycle scripts in the native sandbox").action(async (managerArgs: string[]) => { const manager = selectedManager(); const first = await run(packageManagerCommand(manager), ["install", ...managerArgs, "--ignore-scripts"], { cwd: root(), inherit: true }); if (first.code !== 0) { process.exitCode = first.code; return; } if (!(await canary(root(), manager))) throw new Error("Lifecycle interception could not be verified. CapLock refused to execute dependency scripts."); const config = readConfig(root()); const env = { ...process.env, npm_config_script_shell: shellPath(), CAPLOCK_MODE: "enforce", CAPLOCK_PROJECT_ROOT: root(), CAPLOCK_RUN_ID: randomUUID(), CAPLOCK_STATE_DIR: path.join(root(), STATE_DIR_NAME), CAPLOCK_TIMEOUT_SECONDS: String(config.execution.timeoutSeconds), CAPLOCK_DEBUG: program.opts().debug ? "1" : "" }; const second = await run(packageManagerCommand(manager), ["rebuild", "--foreground-scripts"], { cwd: root(), env, inherit: true, timeoutMs: config.execution.timeoutSeconds * 1000 }); process.exitCode = second.code === 0 ? EXIT.success : EXIT.blocked; });
program.command("inspect").action(() => { for (const p of readLockfile(root()).packages) console.log(`${p.package.name}@${p.package.version} ${p.lifecycle.event}: ${p.lifecycle.command} [network=${p.policy.network}]`); });
program.command("diff").action(() => { const lock = readLockfile(root()); const current = scan(root()); const changed = current.filter((x) => !findLock(lock, x)); if (!changed.length) console.log(pc.green("✓ No unreviewed lifecycle scripts.")); else { for (const x of changed) console.log(pc.yellow(`review required: ${x.package.name}@${x.package.version} ${x.lifecycle.event}`)); process.exitCode = 1; } });
program.command("audit").description("Report risky approved capabilities").action(() => { const risky = readLockfile(root()).packages.filter((entry) => entry.policy.network === "host" || (entry.policy.filesystem?.write?.length ?? 0) > 0); if (!risky.length) console.log("No broad capabilities are approved."); for (const entry of risky) console.log(`${entry.package.name}@${entry.package.version}: ${entry.policy.network === "host" ? "host network" : "additional writable paths"}`); });
program.command("reset").description("Remove generated CapLock state").action(() => { rmSync(path.join(root(), STATE_DIR_NAME), { recursive: true, force: true }); console.log("Removed .caplock state. Your dependencies were not changed."); });
program.command("explain <topic> [name]").description("Explain effective policy behavior").action((topic: string, name?: string) => { if (topic === "env" && name) console.log(`${name}: environment is deny-by-default; explicit values are filtered if their names look secret.`); else console.log("Default policy: synthetic HOME, filtered environment, package-only writes, and no network."); });
program.command("version").description("Print diagnostics useful for bug reports").action(async () => { const { selectSandboxBackend } = await import("./sandbox/backend.js"); console.log(`${PRODUCT_NAME} 0.1.0\nPackage: ${PACKAGE_NAME}\nNode: ${process.version}\nPlatform: ${process.platform}/${process.arch}\nBackend: ${selectSandboxBackend().id}`); });
program.command("ci").action(async () => { const manager = selectedManager(); const command = manager === "pnpm" ? "install" : "ci"; const result = await run(packageManagerCommand(manager), [command, "--ignore-scripts", ...(manager === "pnpm" ? ["--frozen-lockfile"] : [])], { cwd: root(), inherit: true }); if (result.code !== 0) { process.exitCode = result.code; return; } await program.parseAsync(["node", CLI_NAME, "install"]); });
program.parseAsync().catch((error: unknown) => { console.error(pc.red(error instanceof Error ? error.message : String(error))); if (program.opts().debug && error instanceof Error) console.error(error.stack); process.exitCode = 1; });
