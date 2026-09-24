import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { defaultPolicy } from "../../src/policy.js";
import { MacOSSandboxBackend } from "../../src/sandbox/macos.js";

const suite = process.platform === "darwin" ? describe : describe.skip;

suite("macOS Seatbelt production sandbox contract", () => {
  it("enforces package-only writes, synthetic HOME, hidden secrets, and network:none", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-macos-contract-"));
    try {
      const pkg = path.join(root, "node_modules", "fixture"); const sibling = path.join(root, "sibling");
      mkdirSync(pkg, { recursive: true }); mkdirSync(sibling); writeFileSync(path.join(root, ".env"), "TOP_SECRET"); writeFileSync(path.join(pkg, "package.json"), '{"name":"fixture","version":"1.0.0"}');
      const backend = new MacOSSandboxBackend(); const available = await backend.checkAvailability();
      expect(available.available, available.detail).toBe(true);
      const command = "test \"$HOME\" != \"$REAL_HOME\" && test -z \"$CAPLOCK_TEST_SECRET\" && echo allowed > allowed && ! test -r '" + path.join(root, ".env") + "' && ! touch '" + path.join(sibling, "escape") + "' && ! /usr/bin/nc -zw1 1.1.1.1 53";
      const result = await backend.run({ executable: "/bin/sh", args: ["-c", command] }, defaultPolicy(), { projectRoot: root, identity: { name: "fixture", version: "1.0.0", packageDir: pkg, packageJsonPath: path.join(pkg, "package.json") }, timeoutMs: 15_000 });
      expect(result.code, `Seatbelt contract exit=${result.code}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`).toBe(0);
      expect(existsSync(path.join(pkg, "allowed"))).toBe(true); expect(existsSync(path.join(sibling, "escape"))).toBe(false);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
