import { existsSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { commandExists, packageManagerCommand, run } from "../../src/process.js";

const suite = ["win32", "linux", "darwin"].includes(process.platform) ? describe : describe.skip;
const cli = path.resolve("dist", "cli.js");
const packageMetadata = JSON.parse(readFileSync(path.resolve("package.json"), "utf8")) as { name: string; version: string };

async function fixture(root: string): Promise<string> {
  const dep = path.join(root, "fixture-dependency"); mkdirSync(dep, { recursive: true });
  writeFileSync(path.join(dep, "attack.js"), `
const fs = require('node:fs');
const path = require('node:path');
const dgram = require('node:dgram');
const { spawnSync } = require('node:child_process');
const root = path.resolve(process.cwd(), '..', '..');
const denied = (action) => { try { action(); return false; } catch (error) { return error && (error.code === 'EPERM' || error.code === 'EACCES'); } };
const resultPath = 'caplock-attack-results.json';
const result = { stage: 'start', package_write: false, project_env_read: false, project_root_write: false, secret_env: false, trusted_preload_present: false, child_spawn_started: false, child_spawn_returned: false, child_started: false, child_exit: null, child_escape: false, parent_continues: false, network_started: false, network_finished: false, network: false, error: null };
const checkpoint = (stage, values = {}) => { Object.assign(result, values, { stage }); fs.writeFileSync(resultPath, JSON.stringify(result)); };
const deniedNetworkError = (error) => !error || ['EACCES', 'EPERM', 'ENETUNREACH', 'EHOSTUNREACH'].includes(error.code);
const lifecycleSucceeded = () => result.package_write && result.project_env_read && result.project_root_write && result.secret_env && result.child_started && result.child_spawn_returned && result.child_exit === 0 && result.child_escape && result.parent_continues && result.network;
process.once('uncaughtException', (error) => { checkpoint('uncaught_exception', { error: error && (error.code || error.message || 'uncaught') }); process.exitCode = 2; });
try {
  fs.writeFileSync('caplock-lifecycle-marker', 'intercepted'); checkpoint('package_write', { package_write: true });
  checkpoint('project_env_read_started'); result.project_env_read = denied(() => fs.readFileSync(path.join(root, '.env'))); checkpoint('project_env_read', { project_env_read: result.project_env_read });
  checkpoint('project_root_write_started'); result.project_root_write = denied(() => fs.writeFileSync(path.join(root, 'CAPLOCK_ESCAPE.txt'), 'escape')); checkpoint('project_root_write', { project_root_write: result.project_root_write });
  result.secret_env = process.env.CAPLOCK_TEST_SECRET === undefined; checkpoint('secret_env', { secret_env: result.secret_env });
  result.trusted_preload_present = typeof process.env.NODE_OPTIONS === 'string' && process.env.NODE_OPTIONS.includes('caplock-pipe-shim.node');
  checkpoint('trusted_preload_environment', { trusted_preload_present: result.trusted_preload_present });
  checkpoint('child_spawn_started', { child_spawn_started: true });
  const child = spawnSync(process.execPath, ['-e', "require('node:fs').writeFileSync('caplock-child-entered.marker','ok');process.exit(0)"], { timeout: 3000 });
  result.child_spawn_returned = true; result.child_started = typeof child.pid === 'number'; result.child_exit = child.status;
  checkpoint('child_spawn_returned', { child_spawn_returned: result.child_spawn_returned, child_started: result.child_started, child_exit: result.child_exit, child_error: child.error && child.error.code || null });
  const escapeChild = spawnSync(process.execPath, ['-e', "const fs=require('node:fs'),path=require('node:path');try{fs.writeFileSync(path.resolve(process.cwd(),'..','..','CHILD_ESCAPE.txt'),'escape');process.exit(9)}catch(error){process.exit(error&&(error.code==='EPERM'||error.code==='EACCES')?0:8)}"], { timeout: 3000 });
  result.child_escape = escapeChild.status === 0 && !fs.existsSync(path.join(root, 'CHILD_ESCAPE.txt'));
  checkpoint('child_escape', { child_escape: result.child_escape, child_escape_exit: escapeChild.status, child_escape_error: escapeChild.error && escapeChild.error.code || null });
  result.parent_continues = true; checkpoint('parent_continues', { parent_continues: true });
} catch (error) {
  checkpoint('probe_exception', { error: error && (error.code || error.message || 'exception') }); process.exitCode = 2;
}
if (process.exitCode) {
  checkpoint('failed_before_network');
} else {
  const socket = dgram.createSocket('udp4'); let settled = false;
  checkpoint('network_started', { network_started: true });
  const finish = (value, stage, error) => {
    if (settled) return; settled = true; clearTimeout(timer);
    try { socket.close(); } catch { /* socket may already be closed */ }
    checkpoint(stage, { network: value, network_finished: true, error: error && (error.code || error.message || null) });
    process.exitCode = lifecycleSucceeded() ? 0 : 2;
  };
  const timer = setTimeout(() => finish(true, 'network_timeout'), 2000);
  socket.once('message', () => finish(false, 'network_message'));
  socket.once('error', (error) => finish(deniedNetworkError(error), 'network_error', error));
  socket.send(Buffer.from([0, 1, 0, 0]), 53, '8.8.8.8', (error) => { if (error) finish(deniedNetworkError(error), 'network_send_error', error); });
}
`);
  const syntax = await run(process.execPath, ["--check", path.join(dep, "attack.js")], { cwd: dep, timeoutMs: 10_000 });
  expect(syntax.code, `generated attack.js must parse before packaging:\n${syntax.stderr}`).toBe(0);
  writeFileSync(path.join(dep, "package.json"), JSON.stringify({ name: "fixture-dependency", version: "1.0.0", scripts: { postinstall: "node attack.js" } }));
  const packed = await run(packageManagerCommand("npm"), ["pack", "--cache", path.join(root, ".npm-cache")], { cwd: dep, timeoutMs: 60_000 });
  expect(packed.code, packed.stderr).toBe(0);
  const filename = packed.stdout.trim().split(/\r?\n/).at(-1)!;
  const tarball = path.join(dep, filename);
  expect(existsSync(tarball), `npm pack did not create ${filename}`).toBe(true);
  writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "caplock-e2e", version: "1.0.0", dependencies: { "fixture-dependency": tarball } }));
  return tarball;
}

suite("npm lifecycle E2E", () => {
  it("ignores scripts during acquisition and runs only an approved lifecycle through CapLock", async () => {
    expect(existsSync(cli), "build before E2E").toBe(true); expect(await commandExists("npm")).toBe(true);
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-npm-e2e-"));
    try {
      await fixture(root);
      const npmCache = path.join(root, ".npm-cache");
      // Simulate `npm run test:e2e:npm`: these outer lifecycle values must not
      // become the dependency postinstall identity.
      writeFileSync(path.join(root, ".env"), "CAPLOCK_TEST_SECRET=must-not-leak\n");
      const npmEnv = { ...process.env, CAPLOCK_TEST_SECRET: "must-not-leak", npm_config_cache: npmCache, NPM_CONFIG_CACHE: npmCache, npm_lifecycle_event: "outer-event", npm_lifecycle_script: "outer-script", npm_package_json: path.resolve("package.json"), npm_package_name: packageMetadata.name, npm_package_version: packageMetadata.version, npm_command: "run test:e2e:npm" };
      const ignored = await run(packageManagerCommand("npm"), ["install", "--ignore-scripts"], { cwd: root, env: npmEnv, timeoutMs: 60_000 });
      expect(ignored.code, ignored.stderr).toBe(0);
      const packageDir = path.join(root, "node_modules", "fixture-dependency");
      expect(lstatSync(packageDir).isSymbolicLink(), "packed dependency must not be linked").toBe(false);
      expect(realpathSync.native(packageDir).startsWith(realpathSync.native(path.join(root, "node_modules"))), "packed dependency must resolve inside node_modules").toBe(true);
      const marker = path.join(packageDir, "caplock-lifecycle-marker"); expect(existsSync(marker)).toBe(false);
      expect((await run(process.execPath, [cli, "init"], { cwd: root })).code).toBe(0);
      expect((await run(process.execPath, [cli, "learn", "--yes"], { cwd: root })).code).toBe(0);
      const installed = await run(process.execPath, [cli, "install"], { cwd: root, env: { ...npmEnv, CAPLOCK_DEBUG: "1" }, timeoutMs: 90_000 });
      const progressPath = path.join(packageDir, "caplock-attack-results.json");
      const progress = existsSync(progressPath) ? readFileSync(progressPath, "utf8") : "<missing>";
      const lifecycleMarker = existsSync(path.join(packageDir, "caplock-lifecycle-marker"));
      const childEntered = existsSync(path.join(packageDir, "caplock-child-entered.marker"));
      const shimEntered = existsSync(path.join(packageDir, "caplock-pipe-shim-entered.marker"));
      const shimInstalled = existsSync(path.join(packageDir, "caplock-pipe-shim-installed.marker"));
      const shimEnteredPids = shimEntered ? readFileSync(path.join(packageDir, "caplock-pipe-shim-entered.marker"), "utf8") : "<missing>";
      const shimInstalledPids = shimInstalled ? readFileSync(path.join(packageDir, "caplock-pipe-shim-installed.marker"), "utf8") : "<missing>";
      const shimPaths = existsSync(path.join(packageDir, "caplock-pipe-shim-paths.log")) ? readFileSync(path.join(packageDir, "caplock-pipe-shim-paths.log"), "utf8") : "<missing>";
      expect(installed.code, `${installed.stdout}\n${installed.stderr}\nlifecycle marker: ${lifecycleMarker}; attack progress: ${progress}\nchild entered: ${childEntered}; shim entered: ${shimEntered} (${shimEnteredPids}); shim installed: ${shimInstalled} (${shimInstalledPids})\nshim paths: ${shimPaths}`).toBe(0);
      expect(readFileSync(marker, "utf8")).toBe("intercepted");
      if (process.platform === "win32") {
        const enteredPids = new Set(shimEnteredPids.trim().split(/\s+/));
        const installedPids = new Set(shimInstalledPids.trim().split(/\s+/));
        expect(shimEntered).toBe(true);
        expect(shimInstalled).toBe(true);
        expect(installedPids.size, "parent and both default-pipe children must initialize their own shim").toBeGreaterThanOrEqual(3);
        expect(installedPids).toEqual(enteredPids);
      }
      const attack = JSON.parse(readFileSync(progressPath, "utf8")) as Record<string, unknown>;
      expect(attack).toMatchObject({ package_write: true, project_env_read: true, project_root_write: true, secret_env: true, child_spawn_started: true, child_spawn_returned: true, child_started: true, child_escape: true, child_exit: 0, parent_continues: true, network_started: true, network_finished: true, network: true });
      expect(existsSync(path.join(root, "CAPLOCK_ESCAPE.txt"))).toBe(false);
      expect(existsSync(path.join(root, "CHILD_ESCAPE.txt"))).toBe(false);
      expect(existsSync(path.join(packageDir, "caplock-child-entered.marker"))).toBe(true);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }, 120_000);

  it("refuses a root-project lifecycle instead of classifying it as a dependency", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-npm-local-"));
    try {
      const command = "node -e \"process.exit(0)\"";
      writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "caplock-local", version: "1.0.0", scripts: { postinstall: command } }));
      const result = await run(process.execPath, [path.resolve("dist", "shell.js"), "-c", command], { cwd: root, env: { ...process.env, CAPLOCK_PROJECT_ROOT: root, npm_package_json: path.join(root, "package.json"), npm_lifecycle_event: "postinstall", npm_lifecycle_script: command } });
      expect(result.code).toBe(1);
      expect(result.stderr).toContain("CapLock blocked lifecycle: package root is outside node_modules");
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
