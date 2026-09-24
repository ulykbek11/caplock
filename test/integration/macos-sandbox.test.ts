import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
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
      const policy = defaultPolicy(); policy.env!.allow!.push("REAL_HOME");
      const command = "echo home-check >&2; test \"$HOME\" != \"$REAL_HOME\" || exit 11; echo secret-check >&2; test -z \"$CAPLOCK_TEST_SECRET\" || exit 12; echo tmp-check >&2; test -n \"$TMPDIR\" || exit 13; echo package-write >&2; echo allowed > allowed || exit 14; echo project-read >&2; test ! -r '" + path.join(root, ".env") + "' || exit 15; echo sibling-write >&2; touch '" + path.join(sibling, "escape") + "' 2>/dev/null && exit 16; exit 0";
      const oldDebug = process.env.CAPLOCK_DEBUG; process.env.CAPLOCK_DEBUG = "1";
      let result;
      try { result = await backend.run({ executable: "/bin/sh", args: ["-c", command] }, policy, { projectRoot: root, identity: { name: "fixture", version: "1.0.0", packageDir: pkg, packageJsonPath: path.join(pkg, "package.json") }, childEnv: { ...process.env, REAL_HOME: root, CAPLOCK_TEST_SECRET: "CAPLOCK_TEST_SECRET_MUST_NOT_LEAK" }, timeoutMs: 15_000 }); }
      finally { if (oldDebug === undefined) delete process.env.CAPLOCK_DEBUG; else process.env.CAPLOCK_DEBUG = oldDebug; }
      expect(result.code, `Seatbelt contract exit=${result.code}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`).toBe(0);
      expect(existsSync(path.join(pkg, "allowed"))).toBe(true); expect(existsSync(path.join(sibling, "escape"))).toBe(false);

      const server = net.createServer((socket) => socket.end("caplock\n"));
      await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => resolve()); });
      const address = server.address(); if (!address || typeof address === "string") throw new Error("Could not start controlled localhost network endpoint");
      const script = "const net=require('node:net');const s=net.createConnection({host:'127.0.0.1',port:Number(process.argv[1])});s.once('connect',()=>{s.end();process.exit(0)});s.once('error',()=>process.exit(2));setTimeout(()=>process.exit(3),3000)";
      try {
        const none = await backend.run({ executable: process.execPath, args: ["-e", script, String(address!.port)], trustedExecutablePaths: [process.execPath] }, defaultPolicy(), { projectRoot: root, identity: { name: "fixture", version: "1.0.0", packageDir: pkg, packageJsonPath: path.join(pkg, "package.json") }, timeoutMs: 10_000 });
        expect(none.code, `Seatbelt network:none unexpectedly connected; stderr=${none.stderr}`).not.toBe(0);
        const hostPolicy = defaultPolicy(); hostPolicy.network = "host";
        const host = await backend.run({ executable: process.execPath, args: ["-e", script, String(address!.port)], trustedExecutablePaths: [process.execPath] }, hostPolicy, { projectRoot: root, identity: { name: "fixture", version: "1.0.0", packageDir: pkg, packageJsonPath: path.join(pkg, "package.json") }, timeoutMs: 10_000 });
        expect(host.code, `Seatbelt network:host failed: ${host.stderr}`).toBe(0);
      } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
