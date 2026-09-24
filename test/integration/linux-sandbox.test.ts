import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import net from "node:net";
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
      const command = "test \"$HOME\" = /home/caplock && test -z \"$CAPLOCK_TEST_SECRET\" && echo allowed > allowed && ! test -r '" + path.join(root, ".env") + "' && ! touch '" + path.join(sibling, "escape") + "'";
      const result = await backend.run({ executable: "/bin/sh", args: ["-c", command] }, policy, { projectRoot: root, identity: { name: "fixture", version: "1.0.0", packageDir: pkg, packageJsonPath: path.join(pkg, "package.json") }, childEnv: { ...process.env, CAPLOCK_TEST_SECRET: "CAPLOCK_SECRET_DO_NOT_LEAK" }, timeoutMs: 15_000 });
      expect(result.code, result.stderr).toBe(0);
      expect(readFileSync(path.join(pkg, "allowed"), "utf8")).toContain("allowed");
      expect(existsSync(path.join(sibling, "escape"))).toBe(false);

      const server = net.createServer((socket) => { socket.on("error", () => undefined); socket.end("caplock\n"); });
      await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => resolve()); });
      const address = server.address(); if (!address || typeof address === "string") throw new Error("Could not start controlled localhost network endpoint");
      const script = "const n=require('node:net'),s=n.createConnection({host:'127.0.0.1',port:Number(process.argv[1])});s.once('connect',()=>{s.end();process.exit(0)});s.once('error',()=>process.exit(2));setTimeout(()=>process.exit(3),3000)";
      try {
        const context = { projectRoot: root, identity: { name: "fixture", version: "1.0.0", packageDir: pkg, packageJsonPath: path.join(pkg, "package.json") }, childEnv: { ...process.env, CAPLOCK_TEST_SECRET: "CAPLOCK_SECRET_DO_NOT_LEAK" }, timeoutMs: 10_000 };
        const none = await backend.run({ executable: process.execPath, args: ["-e", script, String(address.port)], trustedExecutablePaths: [process.execPath] }, policy, context);
        expect(none.code, "seccomp must deny a real TCP connection").not.toBe(0);
        const hostPolicy = { ...policy, network: "host" as const };
        const host = await backend.run({ executable: process.execPath, args: ["-e", script, String(address.port)], trustedExecutablePaths: [process.execPath] }, hostPolicy, context);
        expect(host.code, `network:host did not reach the controlled endpoint: ${host.stderr}`).toBe(0);
      } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
