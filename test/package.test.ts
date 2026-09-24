import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { lifecycleFromPackage } from "../src/package.js";

describe("lifecycle invocation identity", () => {
  it("derives the event from a dependency manifest when npm inherits a parent event", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-package-"));
    try {
      writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0", scripts: { postinstall: "node build.js" } }));
      expect(lifecycleFromPackage(root, "node build.js")).toMatchObject({ event: "postinstall", command: "node build.js" });
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it("fails closed for an unknown or ambiguous command", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-package-"));
    try {
      mkdirSync(path.join(root, "nested"));
      writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0", scripts: { install: "node same.js", postinstall: "node same.js" } }));
      expect(lifecycleFromPackage(root, "node missing.js")).toBeUndefined();
      expect(lifecycleFromPackage(root, "node same.js")).toBeUndefined();
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
