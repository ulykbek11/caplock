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

  it("keeps a nested Node child contained and bounded", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-windows-nested-"));
    const packageDir = path.join(root, "node_modules", "fixture");
    try {
      mkdirSync(packageDir, { recursive: true });
      writeFileSync(path.join(packageDir, "package.json"), '{"name":"fixture","version":"1.0.0"}');
      writeFileSync(path.join(packageDir, "nested.js"), "const fs=require('node:fs'),cp=require('node:child_process'),path=require('node:path');const child=cp.spawnSync(process.execPath,['-e',\"const fs=require('node:fs'),path=require('node:path');try{fs.writeFileSync(path.resolve(process.cwd(),'..','..','nested-escape'),'x');process.exit(9)}catch(e){process.exit(e&&(e.code==='EPERM'||e.code==='EACCES')?0:8)}\"],{timeout:3000});fs.writeFileSync('nested-result.json',JSON.stringify({started:typeof child.pid==='number',status:child.status,error:child.error?.code,parentContinued:true,escaped:fs.existsSync(path.join(process.cwd(),'..','..','nested-escape'))}));process.exit(child.status===0?0:2);");
      const result = await new WindowsSandboxBackend().run({ executable: process.execPath, args: ["--preserve-symlinks-main", "nested.js"], cwd: packageDir, trustedExecutablePaths: [process.execPath] }, defaultPolicy(), { projectRoot: root, identity: { name: "fixture", version: "1.0.0", packageDir, packageJsonPath: path.join(packageDir, "package.json") }, controlEnv: process.env, childEnv: process.env, timeoutMs: 12_000 });
      expect(result.code, `outer watchdog or nested child failure: ${result.stderr}`).toBe(0);
      expect(JSON.parse(readFileSync(path.join(packageDir, "nested-result.json"), "utf8"))).toMatchObject({ started: true, status: 0, parentContinued: true, escaped: false });
      expect(existsSync(path.join(root, "nested-escape"))).toBe(false);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }, 20_000);

  it("actively denies network:none and permits the same configured-resolver DNS request under network:host", async () => {
    const result = await runWindowsNetworkContract();
    expect(result.defaultDeny, result.detail).toBe(true);
    expect(result.hostAllow, result.detail).toBe(true);
  }, 45_000);

  it("drains a surviving descendant before removing its staged runtime and open temp file", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-windows-cleanup-"));
    const packageDir = path.join(root, "node_modules", "fixture");
    const sandboxRoot = path.join(root, "owned-run");
    try {
      mkdirSync(packageDir, { recursive: true });
      writeFileSync(path.join(packageDir, "package.json"), '{"name":"fixture","version":"1.0.0"}');
      const child = "const fs=require('node:fs'),path=require('node:path');fs.openSync(path.join(process.env.TEMP,'held-open'),'w');fs.writeFileSync('child-ready',String(process.pid));setInterval(()=>{},1000)";
      const parent = `const fs=require('node:fs');require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(child)}]);setInterval(()=>{if(fs.existsSync('child-ready'))process.exit(0)},10)`;
      const result = await new WindowsSandboxBackend().run({ executable: process.execPath, args: ["-e", parent], trustedExecutablePaths: [process.execPath] }, defaultPolicy(), { projectRoot: root, sandboxRoot, identity: { name: "fixture", version: "1.0.0", packageDir, packageJsonPath: path.join(packageDir, "package.json") }, controlEnv: process.env, childEnv: process.env, timeoutMs: 12_000 });
      expect(result.code, result.stderr).toBe(0);
      const childPid = Number(readFileSync(path.join(packageDir, "child-ready"), "utf8"));
      expect(childPid).toBeGreaterThan(0);
      expect(() => process.kill(childPid, 0)).toThrow();
      expect(existsSync(sandboxRoot), "owned run tree must be removed before backend returns").toBe(false);
    } finally { rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
  }, 20_000);
});
