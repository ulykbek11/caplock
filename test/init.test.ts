import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { run } from "../src/process.js";

describe("caplock init project state", () => {
  it("keeps reviewed policy and lock state available to commit", async () => {
    const project = mkdtempSync(path.join(os.tmpdir(), "caplock-init-"));
    try {
      writeFileSync(path.join(project, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0" }));
      const tsx = path.resolve("node_modules/tsx/dist/cli.mjs");
      const cli = path.resolve("src/cli.ts");
      const result = await run(process.execPath, [tsx, cli, "init"], { cwd: project, timeoutMs: 15_000 });
      expect(result.code, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(existsSync(path.join(project, ".caplock", "config.yaml"))).toBe(true);
      expect(existsSync(path.join(project, ".caplock", "caplock.lock"))).toBe(true);
      expect(existsSync(path.join(project, ".gitignore"))).toBe(false);
      expect(readFileSync(path.join(project, ".caplock", "caplock.lock"), "utf8")).toContain("packages: []");
    } finally { rmSync(project, { recursive: true, force: true }); }
  });
});
