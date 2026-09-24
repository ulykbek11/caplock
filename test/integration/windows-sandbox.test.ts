import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { run } from "../../src/process.js";
import { defaultPolicy } from "../../src/policy.js";
import { runWindowsNetworkContract, WindowsSandboxBackend } from "../../src/sandbox/windows.js";

/* This suite deliberately invokes the shipped native executable. It is enabled
 * by verify:windows / test:windows-native rather than being simulated on other OSes. */
const enabled = process.platform === "win32";
const suite = enabled ? describe : describe.skip;
const helper = path.resolve("native/bin/caplock-sandbox.exe");

suite("Windows AppContainer production helper", () => {
  it("documents its production entry points", async () => {
    expect(existsSync(helper)).toBe(true);
    const result = await run(helper, ["--help"]);
    expect(result.code).toBe(0); expect(result.stdout).toContain("--selftest");
  });

  it("uses the production launch path for its identity, ACL, and cleanup probe", async () => {
    const result = await run(helper, ["--selftest"], { timeoutMs: 30_000 });
    expect(result.code, result.stderr).toBe(0);
    const probe = JSON.parse(result.stdout.trim()) as Record<string, boolean>;
    expect(probe).toMatchObject({ profileCreated: true, processLaunched: true, tokenIsAppContainer: true, allowedWrite: true, cleanup: true, stage: "complete" });
  });

  it("runs an absolute Node executable inside the production AppContainer backend", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-windows-node-"));
    const packageDir = path.join(root, "node_modules", "fixture");
    try {
      mkdirSync(packageDir, { recursive: true });
      writeFileSync(path.join(packageDir, "package.json"), '{"name":"fixture","version":"1.0.0"}');
      const result = await new WindowsSandboxBackend().run({ executable: process.execPath, args: ["-e", "require('fs').writeFileSync('backend-node-marker','ok')"], trustedExecutablePaths: [process.execPath] }, defaultPolicy(), { projectRoot: root, identity: { name: "fixture", version: "1.0.0", packageDir, packageJsonPath: path.join(packageDir, "package.json") }, controlEnv: process.env, childEnv: { ...process.env, CAPLOCK_TEST_SECRET: "not-visible" }, timeoutMs: 30_000 });
      expect(result.code, result.stderr).toBe(0);
      expect(readFileSync(path.join(packageDir, "backend-node-marker"), "utf8")).toBe("ok");
    } finally { rmSync(root, { recursive: true, force: true }); }
  }, 45_000);

  it("actively denies network:none and permits the same configured-resolver DNS request under network:host", async () => {
    const result = await runWindowsNetworkContract();
    expect(result.defaultDeny, result.detail).toBe(true);
    expect(result.hostAllow, result.detail).toBe(true);
  }, 45_000);
});
