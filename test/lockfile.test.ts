import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { findLock, readLockfile, writeLockfile } from "../src/lockfile.js";
import { defaultPolicy } from "../src/policy.js";
const entry = (name: string) => ({ package: { name, version: "1.0.0" }, lifecycle: { event: "install" as const, command: "node x", hash: "h" }, policy: defaultPolicy() });
describe("lockfile", () => { it("roundtrips and sorts entries", () => { const dir = mkdtempSync(path.join(os.tmpdir(), "caplock-")); try { writeLockfile(dir, { version: 1, packages: [entry("z"), entry("a")] }); const lock = readLockfile(dir); expect(lock.packages.map((x) => x.package.name)).toEqual(["a", "z"]); expect(findLock(lock, entry("a"))?.package.name).toBe("a"); } finally { rmSync(dir, { recursive: true, force: true }); } }); });
