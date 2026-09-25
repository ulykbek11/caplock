import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { smokePackedCli } from "../scripts/packed-smoke.mjs";

describe("packed CLI smoke checks", () => {
  it("runs version, help, doctor and init from the installed package tree", () => {
    const consumerRoot = mkdtempSync(path.join(os.tmpdir(), "caplock-packed-smoke-"));
    const calls = [];
    try {
      const cli = path.join(consumerRoot, "node_modules", "caplock-runtime", "dist", "cli.js");
      mkdirSync(path.dirname(cli), { recursive: true }); writeFileSync(cli, "// packed fixture");
      const binDirectory = path.join(consumerRoot, "node_modules", ".bin"); mkdirSync(binDirectory);
      const suffix = process.platform === "win32" ? ".cmd" : "";
      for (const name of ["caplock", "caplock-shell"]) writeFileSync(path.join(binDirectory, `${name}${suffix}`), "fixture launcher");
      const result = smokePackedCli({ consumerRoot, packageName: "caplock-runtime", expectedVersion: "1.0.0", spawn: (_exe, args, options) => {
        calls.push({ args, options });
        if (args.at(-1) === "--json") return { status: 0, stdout: '{"ready":true}', stderr: "" };
        if (args.at(-1) === "init") {
          mkdirSync(path.join(consumerRoot, ".caplock"), { recursive: true });
          writeFileSync(path.join(consumerRoot, ".caplock", "config.yaml"), "schemaVersion: 1\n");
          writeFileSync(path.join(consumerRoot, ".caplock", "caplock.lock"), "version: 1\npackages: []\n");
        }
        return { status: 0, stdout: args.at(-1) === "version" ? "CapLock 1.0.0" : args.at(-1) === "--help" ? "Usage: caplock [options] [command]" : "ok", stderr: "" };
      } });
      expect(result.cli).toBe(cli);
      expect(calls.map(({ args }) => args.slice(1))).toEqual([["version"], ["--help"], ["doctor", "--json"], ["init"]]);
      expect(calls.every(({ options }) => options.cwd === consumerRoot && options.shell === false)).toBe(true);
    } finally { rmSync(consumerRoot, { recursive: true, force: true }); }
  });

  it("fails on malformed or unready packaged doctor output", () => {
    for (const stdout of ["not json", '{"ready":false}']) {
      const consumerRoot = mkdtempSync(path.join(os.tmpdir(), "caplock-packed-smoke-"));
      try {
        const cli = path.join(consumerRoot, "node_modules", "caplock-runtime", "dist", "cli.js");
        mkdirSync(path.dirname(cli), { recursive: true }); writeFileSync(cli, "// packed fixture");
        const binDirectory = path.join(consumerRoot, "node_modules", ".bin"); mkdirSync(binDirectory);
        const suffix = process.platform === "win32" ? ".cmd" : "";
        for (const name of ["caplock", "caplock-shell"]) writeFileSync(path.join(binDirectory, `${name}${suffix}`), "fixture launcher");
        const spawn = (_exe, args) => args.at(-1) === "--json" ? { status: 0, stdout, stderr: "" } : { status: 0, stdout: args.at(-1) === "version" ? "CapLock 1.0.0" : "Usage: caplock [options] [command]", stderr: "" };
        expect(() => smokePackedCli({ consumerRoot, packageName: "caplock-runtime", expectedVersion: "1.0.0", spawn })).toThrow();
      } finally { rmSync(consumerRoot, { recursive: true, force: true }); }
    }
  });
});
