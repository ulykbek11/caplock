import { existsSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { run } from "../../src/process.js";

/* This suite deliberately invokes the shipped native executable. It is enabled
 * by verify:windows / test:windows-native rather than being simulated on other OSes. */
const enabled = process.platform === "win32" && process.env.CAPLOCK_RUN_WINDOWS_SECURITY === "1";
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
    expect(probe).toEqual({ profileCreated: true, processLaunched: true, tokenIsAppContainer: true, allowedWrite: true, cleanup: true });
  });
});
