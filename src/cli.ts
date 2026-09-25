#!/usr/bin/env node
import { Command } from "commander";
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
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
import { cleanPackageManagerControlEnv, commandExists, packageManagerCommand, run } from "./process.js";
import { identifyPackage } from "./package.js";
import type { LockEntry } from "./types.js";
import { redactText } from "./util.js";

const root = (): string => process.cwd();
function shellPath(): string { return process.platform === "win32" ? path.resolve(path.dirname(process.argv[1] ?? ""), "../native/bin/caplock-shell.exe") : path.join(path.dirname(process.argv[1] ?? ""), "shell.js"); }
export function scan(rootDir: string, requested?: string): LockEntry[] { const base = path.join(rootDir, "node_modules"); const entries: LockEntry[] = []; const seen = new Set<string>(); if (!existsSync(base)) return entries; const visit = (dir: string): void => { if (!existsSync(dir)) return; const resolved = realpathSync.native(dir); if (seen.has(resolved)) return; seen.add(resolved); for (const name of requireDir(dir)) { if (name.startsWith(".")) continue; const packageDir = path.join(dir, name); if (name.startsWith("@")) { visit(packageDir); continue; } const file = path.join(packageDir, "package.json"); if (existsSync(file)) { const pkg = JSON.parse(readFileSync(file, "utf8")) as { name?: string; version?: string; scripts?: Record<string, string> }; if (pkg.name && pkg.version && (!requested || pkg.name === requested)) { const identity = identifyPackage(packageDir, rootDir); for (const event of ["preinstall", "install", "postinstall"] as const) { const command = pkg.scripts?.[event]; if (command) { const policy = defaultPolicy(); if (process.env.CAPLOCK_LEARN_NETWORK === "host") policy.network = "host"; entries.push({ package: { name: pkg.name, version: pkg.version, integrity: identity.integrity }, lifecycle: { event, command, hash: awaitHash(command) }, policy }); } } } } visit(path.join(packageDir, "node_modules")); } }; visit(base); return entries; }
function requireDir(dir: string): string[] { try { return readdirSync(dir); } catch { return []; } }
function awaitHash(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function selectedManager(): "npm" | "pnpm" { const configured = process.env.CAPLOCK_PACKAGE_MANAGER; if (configured === "pnpm" || (!configured && existsSync(path.join(root(), "pnpm-lock.yaml")))) return "pnpm"; return "npm"; }
function rebuildArgs(manager: "npm" | "pnpm"): string[] { return manager === "npm" ? ["rebuild", "--foreground-scripts"] : ["rebuild", "--pending"]; }
async function canary(project: string, manager: "npm" | "pnpm"): Promise<boolean> {
  if (!(await commandExists(manager))) return false;
  const temp = path.join(os.tmpdir(), `caplock-canary-${Date.now()}-${randomUUID()}`); const marker = path.join(temp, "marker");
  try {
    const canary = path.join(temp, "canary"); mkdirSync(canary, { recursive: true }); writeFileSync(path.join(temp, "package.json"), '{"name":"canary-root","version":"1.0.0","dependencies":{"canary":"file:./canary"}}'); writeFileSync(path.join(canary, "package.json"), '{"name":"canary","version":"1.0.0","scripts":{"install":"echo canary"}}');
    const controlEnv = cleanPackageManagerControlEnv(process.env);
    const acquired = await run(packageManagerCommand(manager), ["install", "--ignore-scripts"], { cwd: temp, env: controlEnv }); if (acquired.code !== 0) return false;
    const args = manager === "pnpm" ? ["--dir", canary, "run", "install"] : rebuildArgs(manager);
    const result = await run(packageManagerCommand(manager), args, { cwd: temp, env: { ...controlEnv, CAPLOCK_NODE: process.execPath, npm_config_script_shell: shellPath(), CAPLOCK_PROJECT_ROOT: project, CAPLOCK_CANARY_MARKER: marker } });
    if (process.env.CAPLOCK_DEBUG && (result.code !== 0 || !existsSync(marker))) console.error(`CapLock ${manager} canary failed: exit=${result.code}; intercepted=${existsSync(marker)}; output=${result.stdout.trim()}; errors=${result.stderr.trim()}`);
    return result.code === 0 && existsSync(marker);
  } finally { rmSync(temp, { recursive: true, force: true }); }
}
async function runPnpmLifecycles(project: string, env: NodeJS.ProcessEnv, timeoutMs: number): Promise<number> {
  for (const entry of readLockfile(project).packages) {
    const packageDir = path.join(project, "node_modules", entry.package.name);
    if (!existsSync(path.join(packageDir, "package.json"))) throw new Error(`CapLock requires review: approved pnpm package is not installed: ${entry.package.name}@${entry.package.version}`);
    // pnpm v10 does not replay ignored dependency scripts via `rebuild`.
    // Invoke each reviewed lifecycle through pnpm's own package runner; the
    // canary above proves this path dispatches to the CapLock script shell.
    const result = await run(packageManagerCommand("pnpm"), ["--dir", packageDir, "run", entry.lifecycle.event], { cwd: project, env, inherit: true, timeoutMs });
    if (result.code !== 0) return result.code;
  }
  return 0;
}

const packageVersion = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version as string;
const program = new Command().name(CLI_NAME).description("Sandbox npm install scripts before they touch your machine.").version(packageVersion);
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
  if (proposed.length) console.log(proposed.map((entry) => `${entry.package.name}@${entry.package.version}${entry.package.integrity ? `\n  integrity: ${entry.package.integrity}` : ""}\n  ${entry.lifecycle.event}: ${redactText(entry.lifecycle.command)}\n  proposed network: ${entry.policy.network}`).join("\n\n"));
  if (options.yes) return;
  if (!process.stdin.isTTY) throw new Error("caplock learn requires explicit --yes when stdin is non-interactive.");
  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  try { if (!/^y(es)?$/i.test((await prompt.question("Save this policy? [y/N] ")).trim())) throw new Error("Baseline was not saved."); }
  finally { prompt.close(); }
});
program.command("doctor").action(async () => { const checks = await doctor(root()); const good = checks.every((c) => c.ok); if (program.opts().json) console.log(JSON.stringify({ product: PRODUCT_NAME, ready: good, checks }, null, 2)); else for (const c of checks) console.log(`${c.ok ? pc.green("✓") : pc.red("✗")} ${c.name}: ${c.detail}`); process.exitCode = good ? EXIT.success : (process.platform === "linux" ? EXIT.failure : EXIT.unsupported); });
program.command("init").description("Create CapLock state without changing package.json").action(() => { const state = path.join(root(), STATE_DIR_NAME); mkdirSync(state, { recursive: true, mode: 0o700 }); writeConfig(root()); writeLockfile(root(), readLockfile(root())); console.log(`CapLock initialized.\n\nPackage manager: ${selectedManager()}\nPolicy: ${configPath(root())}\n\nNext:\n  caplock learn`); });
program.command("learn [package]").description("Review installed lifecycle scripts and record a baseline").action((packageName?: string) => { const lock = readLockfile(root()); const found = scan(root(), packageName); if (packageName && found.length === 0) throw new Error(`No lifecycle scripts found for ${packageName} in node_modules.`); for (const item of found) if (!findLock(lock, item)) lock.packages.push(item); writeLockfile(root(), lock); console.log(pc.green(`✓ Recorded ${found.length} lifecycle script(s) in .caplock/caplock.lock`)); });
program.command("install [managerArgs...]").allowUnknownOption(true).description("Install dependencies, then run approved lifecycle scripts in the native sandbox").action(async (managerArgs: string[]) => { const manager = selectedManager(); const controlEnv = cleanPackageManagerControlEnv(process.env); const first = await run(packageManagerCommand(manager), ["install", ...managerArgs, "--ignore-scripts"], { cwd: root(), env: controlEnv, inherit: true }); if (first.code !== 0) { process.exitCode = first.code; return; } if (!(await canary(root(), manager))) throw new Error("Lifecycle interception could not be verified. CapLock refused to execute dependency scripts."); const config = readConfig(root()); const env = { ...controlEnv, CAPLOCK_NODE: process.execPath, npm_config_script_shell: shellPath(), CAPLOCK_PROJECT_ROOT: root(), CAPLOCK_DEBUG: program.opts().debug || process.env.CAPLOCK_DEBUG ? "1" : "" }; const code = manager === "pnpm" ? await runPnpmLifecycles(root(), env, config.execution.timeoutSeconds * 1000) : (await run(packageManagerCommand(manager), rebuildArgs(manager), { cwd: root(), env, inherit: true, timeoutMs: config.execution.timeoutSeconds * 1000 })).code; process.exitCode = code === 0 ? EXIT.success : EXIT.blocked; });
program.command("inspect").action(() => { for (const p of readLockfile(root()).packages) console.log(`${p.package.name}@${p.package.version} ${p.lifecycle.event}: ${redactText(p.lifecycle.command)} [network=${p.policy.network}]`); });
program.command("diff").action(() => { const lock = readLockfile(root()); const current = scan(root()); const changed = current.filter((x) => !findLock(lock, x)); if (!changed.length) console.log(pc.green("✓ No unreviewed lifecycle scripts.")); else { for (const x of changed) console.log(pc.yellow(`review required: ${x.package.name}@${x.package.version} ${x.lifecycle.event}`)); process.exitCode = 1; } });
program.command("audit").description("Report risky approved capabilities").action(() => { const risky = readLockfile(root()).packages.filter((entry) => entry.policy.network === "host" || (entry.policy.filesystem?.write?.length ?? 0) > 0); if (!risky.length) console.log("No broad capabilities are approved."); for (const entry of risky) console.log(`${entry.package.name}@${entry.package.version}: ${entry.policy.network === "host" ? "host network" : "additional writable paths"}`); });
program.command("reset").description("Remove generated CapLock state").action(() => { rmSync(path.join(root(), STATE_DIR_NAME), { recursive: true, force: true }); console.log("Removed .caplock state. Your dependencies were not changed."); });
program.command("explain <topic> [name]").description("Explain effective policy behavior").action((topic: string, name?: string) => { if (topic === "env" && name) console.log(`${name}: environment is deny-by-default; explicit values are filtered if their names look secret.`); else console.log("Default policy: synthetic HOME, filtered environment, package-only writes, and no network."); });
program.command("version").description("Print diagnostics useful for bug reports").action(async () => { const { selectSandboxBackend } = await import("./sandbox/backend.js"); console.log(`${PRODUCT_NAME} ${packageVersion}\nPackage: ${PACKAGE_NAME}\nNode: ${process.version}\nPlatform: ${process.platform}/${process.arch}\nBackend: ${selectSandboxBackend().id}`); });
program.command("ci").action(async () => { const manager = selectedManager(); const command = manager === "pnpm" ? "install" : "ci"; const result = await run(packageManagerCommand(manager), [command, "--ignore-scripts", ...(manager === "pnpm" ? ["--frozen-lockfile"] : [])], { cwd: root(), inherit: true }); if (result.code !== 0) { process.exitCode = result.code; return; } await program.parseAsync(["node", CLI_NAME, "install"]); });
program.parseAsync().catch((error: unknown) => { console.error(pc.red(redactText(error instanceof Error ? error.message : String(error)))); if (program.opts().debug && error instanceof Error) console.error(redactText(error.stack ?? "")); process.exitCode = 1; });
