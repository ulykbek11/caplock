import { describe, expect, it } from "vitest";
import { cleanPackageManagerControlEnv, packageManagerCommand, run } from "../src/process.js";

describe("trusted package-manager command resolution", () => {
  it("removes stale lifecycle metadata while preserving normal control variables", () => {
    const clean = cleanPackageManagerControlEnv({ SystemRoot: "C:\\Windows", npm_lifecycle_event: "outer", npm_lifecycle_script: "outer-script", npm_package_json: "C:\\outer\\package.json", npm_command: "run test", SAFE: "yes" });
    expect(clean).toMatchObject({ SystemRoot: "C:\\Windows", SAFE: "yes" });
    expect(clean.npm_lifecycle_event).toBeUndefined(); expect(clean.npm_lifecycle_script).toBeUndefined(); expect(clean.npm_package_json).toBeUndefined(); expect(clean.npm_command).toBeUndefined();
  });
  it("returns raw executable names without shell quotes", () => {
    for (const manager of ["npm", "pnpm"]) {
      const executable = packageManagerCommand(manager);
      expect(executable.startsWith('"')).toBe(false);
      expect(executable.endsWith('"')).toBe(false);
      expect(executable).toBe(process.platform === "win32" ? `${manager}.cmd` : manager);
    }
  });

  it("runs npm and pnpm version via the E2E runner on Windows", async () => {
    if (process.platform !== "win32") return;
    for (const manager of ["npm", "pnpm"]) {
      const result = await run(packageManagerCommand(manager), ["--version"], { timeoutMs: 30_000 });
      expect(result.code, result.stderr).toBe(0);
      expect(result.stdout.trim()).not.toBe("");
    }
  });
});
