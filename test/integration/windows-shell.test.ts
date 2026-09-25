import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { defaultPolicy } from "../../src/policy.js";
import { writeConfig } from "../../src/config.js";
import { writeLockfile } from "../../src/lockfile.js";
import { cleanPackageManagerControlEnv, run } from "../../src/process.js";
import { sha256 } from "../../src/util.js";

const suite = process.platform === "win32" ? describe : describe.skip;
const shell = path.resolve("native/bin/caplock-shell.exe");
const packageMetadata = JSON.parse(readFileSync(path.resolve("package.json"), "utf8")) as { name: string; version: string };

suite("Windows native lifecycle shell", () => {
  it("matches exact npm metadata and reaches the production backend", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-shell-contract-"));
    const packageDir = path.join(root, "node_modules", "fixture");
    const command = "node -e \"require('fs').writeFileSync('shell-contract-marker','ok')\"";
    try {
      mkdirSync(packageDir, { recursive: true });
      writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "root", version: "1.0.0" }));
      const fixtureManifest = path.join(packageDir, "package.json");
      const fixture = { name: "fixture", version: "1.0.0", scripts: { postinstall: command } };
      writeFileSync(fixtureManifest, JSON.stringify(fixture));
      mkdirSync(path.join(root, ".caplock"));
      writeConfig(root);
      writeLockfile(root, { version: 1, packages: [{ package: { name: "fixture", version: "1.0.0" }, lifecycle: { event: "postinstall", command, hash: sha256(command) }, policy: defaultPolicy() }] });
      // Model npm 11 forwarding an outer `npm run test:security` context.
      // Strip that identity first, then explicitly supply the lifecycle
      // metadata npm would have set for this fixture package.
      const env = cleanPackageManagerControlEnv({
        ...process.env,
        npm_lifecycle_event: "test:security",
        npm_lifecycle_script: "vitest run test/security test/integration",
        npm_package_json: path.resolve("package.json"),
        npm_package_name: "caplock-runtime",
        npm_package_version: packageMetadata.version,
        NPM_LIFECYCLE_EVENT: "test:security",
        NPM_LIFECYCLE_SCRIPT: "vitest run test/security test/integration",
        NPM_PACKAGE_JSON: path.resolve("package.json"),
        NPM_PACKAGE_NAME: "caplock-runtime",
        NPM_PACKAGE_VERSION: packageMetadata.version,
      });
      const lifecycleMetadataKeys = new Set([
        "npm_lifecycle_event", "npm_lifecycle_script", "npm_package_json",
        "npm_package_name", "npm_package_version", "npm_command",
      ]);
      // Windows environment names are case-insensitive even though a JS
      // object can retain differently-cased duplicate keys from its parent.
      for (const key of Object.keys(env)) if (lifecycleMetadataKeys.has(key.toLowerCase())) delete env[key];
      expect(Object.keys(env).some((key) => lifecycleMetadataKeys.has(key.toLowerCase()))).toBe(false);
      Object.assign(env, {
        npm_lifecycle_event: "postinstall",
        npm_lifecycle_script: fixture.scripts.postinstall,
        npm_package_json: fixtureManifest,
        npm_package_name: fixture.name,
        npm_package_version: fixture.version,
      });
      expect(env).toMatchObject({
        npm_lifecycle_event: "postinstall",
        npm_lifecycle_script: command,
        npm_package_json: fixtureManifest,
        npm_package_name: "fixture",
        npm_package_version: "1.0.0",
      });
      const result = await run(shell, ["-c", "node", "-e", command.slice(9, -1)], {
        cwd: packageDir,
        env: { ...env, CAPLOCK_NODE: process.execPath, CAPLOCK_PROJECT_ROOT: root },
        timeoutMs: 30_000,
      });
      expect(result.code, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(readFileSync(path.join(packageDir, "shell-contract-marker"), "utf8")).toBe("ok");
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
