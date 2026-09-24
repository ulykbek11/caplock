import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { defaultPolicy } from "../../src/policy.js";
import { LinuxBubblewrapBackend } from "../../src/sandbox/linux.js";

const suite = process.platform === "linux" ? describe : describe.skip;

suite("Linux production sandbox contract", () => {
  it("enforces package-only writes, a synthetic HOME, secret filtering, and network:none", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-linux-contract-"));
    try {
      const pkg = path.join(root, "node_modules", "fixture"); const sibling = path.join(root, "sibling");
      mkdirSync(pkg, { recursive: true }); mkdirSync(sibling); writeFileSync(path.join(root, ".env"), "TOP_SECRET");
      writeFileSync(path.join(pkg, "package.json"), '{"name":"fixture","version":"1.0.0"}');
      const backend = new LinuxBubblewrapBackend(); const available = await backend.checkAvailability();
      expect(available.available, available.detail).toBe(true);
      const policy = defaultPolicy();
      const command = "test \"$HOME\" = /home/caplock && test -z \"$CAPLOCK_TEST_SECRET\" && echo allowed > allowed && ! test -r '" + path.join(root, ".env") + "' && ! touch '" + path.join(sibling, "escape") + "' && ! /bin/sh -c 'exec 3<>/dev/tcp/1.1.1.1/53'";
      const result = await backend.run({ executable: "/bin/sh", args: ["-c", command] }, policy, { projectRoot: root, identity: { name: "fixture", version: "1.0.0", packageDir: pkg, packageJsonPath: path.join(pkg, "package.json") }, timeoutMs: 15_000 });
      expect(result.code, result.stderr).toBe(0);
      expect(readFileSync(path.join(pkg, "allowed"), "utf8")).toContain("allowed");
      expect(existsSync(path.join(sibling, "escape"))).toBe(false);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
