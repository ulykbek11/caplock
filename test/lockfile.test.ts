import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { findLock, readLockfile, writeLockfile } from "../src/lockfile.js";
import { defaultPolicy } from "../src/policy.js";
import { lockKey } from "../src/lockfile.js";
const entry = (name: string) => ({ package: { name, version: "1.0.0" }, lifecycle: { event: "install" as const, command: "node x", hash: "a".repeat(64) }, policy: defaultPolicy() });
describe("lockfile", () => { it("roundtrips and sorts entries", () => { const dir = mkdtempSync(path.join(os.tmpdir(), "caplock-")); try { writeLockfile(dir, { version: 1, packages: [entry("z"), entry("a")] }); const lock = readLockfile(dir); expect(lock.packages.map((x) => x.package.name)).toEqual(["a", "z"]); expect(findLock(lock, entry("a"))?.package.name).toBe("a"); } finally { rmSync(dir, { recursive: true, force: true }); } }); });

describe("integrity identity", () => {
  it("does not approve same name and version when integrity changes", () => {
    const trusted = { ...entry("a"), package: { name: "a", version: "1.0.0", integrity: "sha512-trusted" } };
    const replaced = { ...entry("a"), package: { name: "a", version: "1.0.0", integrity: "sha512-replaced" } };
    expect(lockKey(trusted)).not.toBe(lockKey(replaced));
    expect(findLock({ version: 1, packages: [trusted] }, replaced)).toBeUndefined();
  });
});

describe("lockfile schema", () => {
  it("rejects a tampered lifecycle hash before it can be selected", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "caplock-"));
    try {
      mkdirSync(path.join(dir, ".caplock"));
      writeFileSync(path.join(dir, ".caplock", "caplock.lock"), "version: 1\npackages:\n  - package: { name: a, version: 1.0.0 }\n    lifecycle: { event: install, command: node x, hash: forged }\n    policy: { filesystem: { read: [], write: [] }, env: { allow: [] }, network: none }\n");
      expect(() => readLockfile(dir)).toThrow("Invalid caplock.lock schema");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
