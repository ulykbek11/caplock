import { existsSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { commandExists, packageManagerCommand, run } from "../../src/process.js";

const suite = ["win32", "linux", "darwin"].includes(process.platform) ? describe : describe.skip;
const cli = path.resolve("dist", "cli.js");
async function fixture(root: string): Promise<void> {
  const dep = path.join(root, "fixture-dependency"); mkdirSync(dep, { recursive: true });
  writeFileSync(path.join(dep, "package.json"), JSON.stringify({ name: "fixture-dependency", version: "1.0.0", scripts: { postinstall: "node -e \"require('fs').writeFileSync('caplock-lifecycle-marker','intercepted')\"" } }));
  const packed = await run(packageManagerCommand("npm"), ["pack", "--cache", path.join(root, ".npm-cache")], { cwd: dep, timeoutMs: 60_000 });
  expect(packed.code, packed.stderr).toBe(0);
  const tarball = path.join(dep, packed.stdout.trim().split(/\r?\n/).at(-1)!);
  expect(existsSync(tarball)).toBe(true);
  writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "caplock-pnpm-e2e", version: "1.0.0", dependencies: { "fixture-dependency": tarball } }));
}
suite("pnpm lifecycle E2E", () => {
  it("proves pnpm lifecycle interception before an approved script can run", async () => {
    expect(existsSync(cli), "build before E2E").toBe(true); expect(await commandExists("pnpm")).toBe(true);
    if (process.platform !== "win32") expect(statSync(path.join(path.dirname(cli), "shell.js")).mode & 0o111, "POSIX script-shell shim must be executable").not.toBe(0);
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-pnpm-e2e-"));
    try {
      await fixture(root);
      const npmCache = path.join(root, ".npm-cache");
      const npmEnv = { ...process.env, npm_config_cache: npmCache, NPM_CONFIG_CACHE: npmCache };
      const ignored = await run(packageManagerCommand("pnpm"), ["install", "--ignore-scripts"], { cwd: root, env: npmEnv, timeoutMs: 60_000 }); expect(ignored.code, ignored.stderr).toBe(0);
      const packageDir = path.join(root, "node_modules", "fixture-dependency");
      expect(realpathSync.native(packageDir).startsWith(realpathSync.native(path.join(root, "node_modules"))), "pnpm dependency must resolve inside node_modules").toBe(true);
      const marker = path.join(packageDir, "caplock-lifecycle-marker"); expect(existsSync(marker)).toBe(false);
      expect((await run(process.execPath, [cli, "init"], { cwd: root })).code).toBe(0); expect((await run(process.execPath, [cli, "learn", "--yes"], { cwd: root })).code).toBe(0);
      const installed = await run(process.execPath, [cli, "install"], { cwd: root, env: process.platform === "win32" ? npmEnv : { ...npmEnv, CAPLOCK_DEBUG: "1" }, timeoutMs: 90_000 }); expect(installed.code, `${installed.stdout}\n${installed.stderr}`).toBe(0);
      expect(readFileSync(marker, "utf8")).toBe("intercepted");
    } finally { rmSync(root, { recursive: true, force: true }); }
  }, 120_000);
});
