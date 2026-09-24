import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { defaultPolicy } from "../../src/policy.js";
import { writeConfig } from "../../src/config.js";
import { writeLockfile } from "../../src/lockfile.js";
import { run } from "../../src/process.js";
import { sha256 } from "../../src/util.js";

const suite = process.platform === "win32" ? describe : describe.skip;
const shell = path.resolve("native/bin/caplock-shell.exe");

suite("Windows native lifecycle shell", () => {
  it("matches exact npm metadata and reaches the production backend", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-shell-contract-"));
    const packageDir = path.join(root, "node_modules", "fixture");
    const command = "node -e \"require('fs').writeFileSync('shell-contract-marker','ok')\"";
    try {
      mkdirSync(packageDir, { recursive: true });
      writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "root", version: "1.0.0" }));
      writeFileSync(path.join(packageDir, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0", scripts: { postinstall: command } }));
      mkdirSync(path.join(root, ".caplock"));
      writeConfig(root);
      writeLockfile(root, { version: 1, packages: [{ package: { name: "fixture", version: "1.0.0" }, lifecycle: { event: "postinstall", command, hash: sha256(command) }, policy: defaultPolicy() }] });
      const result = await run(shell, ["-c", "node", "-e", command.slice(9, -1)], {
        cwd: packageDir,
        env: { ...process.env, CAPLOCK_NODE: process.execPath, CAPLOCK_PROJECT_ROOT: root, npm_lifecycle_event: "postinstall", npm_lifecycle_script: command, npm_package_json: path.join(packageDir, "package.json"), npm_package_name: "fixture", npm_package_version: "1.0.0" },
        timeoutMs: 30_000,
      });
      expect(result.code, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(readFileSync(path.join(packageDir, "shell-contract-marker"), "utf8")).toBe("ok");
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
