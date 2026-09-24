import { existsSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { commandExists, packageManagerCommand, run } from "../../src/process.js";

const suite = ["win32", "linux", "darwin"].includes(process.platform) ? describe : describe.skip;
const cli = path.resolve("dist", "cli.js");

async function fixture(root: string): Promise<string> {
  const dep = path.join(root, "fixture-dependency"); mkdirSync(dep, { recursive: true });
  writeFileSync(path.join(dep, "package.json"), JSON.stringify({ name: "fixture-dependency", version: "1.0.0", scripts: { postinstall: "node -e \"require('fs').writeFileSync('caplock-lifecycle-marker','intercepted')\"" } }));
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
      const npmEnv = { ...process.env, npm_config_cache: npmCache, NPM_CONFIG_CACHE: npmCache, npm_lifecycle_event: "outer-event", npm_lifecycle_script: "outer-script", npm_package_json: path.resolve("package.json"), npm_package_name: "caplock-runtime", npm_package_version: "0.0.0", npm_command: "run test:e2e:npm" };
      const ignored = await run(packageManagerCommand("npm"), ["install", "--ignore-scripts"], { cwd: root, env: npmEnv, timeoutMs: 60_000 });
      expect(ignored.code, ignored.stderr).toBe(0);
      const packageDir = path.join(root, "node_modules", "fixture-dependency");
      expect(lstatSync(packageDir).isSymbolicLink(), "packed dependency must not be linked").toBe(false);
      expect(realpathSync.native(packageDir).startsWith(realpathSync.native(path.join(root, "node_modules"))), "packed dependency must resolve inside node_modules").toBe(true);
      const marker = path.join(packageDir, "caplock-lifecycle-marker"); expect(existsSync(marker)).toBe(false);
      expect((await run(process.execPath, [cli, "init"], { cwd: root })).code).toBe(0);
      expect((await run(process.execPath, [cli, "learn", "--yes"], { cwd: root })).code).toBe(0);
      const installed = await run(process.execPath, [cli, "install"], { cwd: root, env: npmEnv, timeoutMs: 90_000 });
      expect(installed.code, `${installed.stdout}\n${installed.stderr}`).toBe(0);
      expect(readFileSync(marker, "utf8")).toBe("intercepted");
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
