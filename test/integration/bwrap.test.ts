import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { defaultPolicy } from "../../src/policy.js";
import { LinuxBubblewrapBackend } from "../../src/sandbox/linux.js";

const suite = process.platform === "linux" ? describe : describe.skip;

suite("Bubblewrap production integration", () => {
  it("runs under real network isolation without Bubblewrap loopback setup", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-bwrap-contract-"));
    try {
      const packageDir = path.join(root, "node_modules", "fixture");
      mkdirSync(packageDir, { recursive: true });
      writeFileSync(path.join(packageDir, "package.json"), '{"name":"fixture","version":"1.0.0"}');
      const backend = new LinuxBubblewrapBackend();
      const available = await backend.checkAvailability();
      expect(available.available, available.detail).toBe(true);
      const result = await backend.run(
        { executable: "/bin/sh", args: ["-c", "test \"$HOME\" = /home/caplock && echo isolated > marker && ! getent hosts example.com"] },
        defaultPolicy(),
        { projectRoot: root, identity: { name: "fixture", version: "1.0.0", packageDir, packageJsonPath: path.join(packageDir, "package.json") }, timeoutMs: 15_000 },
      );
      expect(result.code, result.stderr).toBe(0);
      expect(existsSync(path.join(packageDir, "marker"))).toBe(true);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
