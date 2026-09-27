import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import net from "node:net";
import dgram from "node:dgram";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { defaultPolicy } from "../../src/policy.js";
import { LinuxBubblewrapBackend } from "../../src/sandbox/linux.js";

const suite = process.platform === "linux" ? describe : describe.skip;

suite("Linux production sandbox contract", () => {
  it("enforces package-only writes, a synthetic HOME, secret filtering, and network:none", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-linux-contract-"));
    try {
      // Poison the actual environment inherited by bwrap, not just childEnv.
      vi.stubEnv("CAPLOCK_TEST_SECRET", "synthetic-secret");
      vi.stubEnv("CAPLOCK_UNLISTED_VALUE", "synthetic-unlisted");
      const pkg = path.join(root, "node_modules", "fixture"); const sibling = path.join(root, "sibling");
      mkdirSync(pkg, { recursive: true }); mkdirSync(sibling); writeFileSync(path.join(root, ".env"), "TOP_SECRET");
      writeFileSync(path.join(pkg, "package.json"), '{"name":"fixture","version":"1.0.0"}');
      writeFileSync(path.join(root, "package.json"), '{"name":"project","version":"1.0.0"}');
      writeFileSync(path.join(sibling, "approved.txt"), "approved-read");
      const backend = new LinuxBubblewrapBackend(); const available = await backend.checkAvailability();
      expect(available.available, available.detail).toBe(true);
      const policy = defaultPolicy();
      const command = "test \"$HOME\" = /home/caplock && test -z \"$CAPLOCK_TEST_SECRET\" && echo allowed > allowed && ! test -r '" + path.join(root, ".env") + "' && ! touch '" + path.join(sibling, "escape") + "'";
      const result = await backend.run({ executable: "/bin/sh", args: ["-c", command] }, policy, { projectRoot: root, identity: { name: "fixture", version: "1.0.0", packageDir: pkg, packageJsonPath: path.join(pkg, "package.json") }, childEnv: { ...process.env, CAPLOCK_TEST_SECRET: "CAPLOCK_SECRET_DO_NOT_LEAK" }, timeoutMs: 15_000 });
      expect(result.code, result.stderr).toBe(0);
      expect(readFileSync(path.join(pkg, "allowed"), "utf8")).toContain("allowed");
      expect(existsSync(path.join(sibling, "escape"))).toBe(false);

      const context = { projectRoot: root, identity: { name: "fixture", version: "1.0.0", packageDir: pkg, packageJsonPath: path.join(pkg, "package.json") }, childEnv: { ...process.env, npm_lifecycle_event: "postinstall", NODE_NO_WARNINGS: "1" }, timeoutMs: 10_000 };
      const environmentChecks = `
        const assert = require('node:assert/strict');
        const fs = require('node:fs');
        const root = ${JSON.stringify(root)};
        const path = require('node:path');
        const denied = action => assert.throws(action, error => ['EPERM','EACCES','ENOENT','EROFS'].includes(error.code));
        denied(() => fs.readFileSync(path.join(root, '.env')));
        // Check in-sandbox results, not only the host filesystem: an escape
        // into a writable synthetic /tmp tree leaves no host-side evidence.
        denied(() => fs.writeFileSync(path.join(root, 'escape-' + process.pid), 'escape'));
        denied(() => fs.mkdirSync(path.join(root, 'new-sibling-' + process.pid)));
        denied(() => fs.writeFileSync(path.join(root, 'sibling', 'escape-' + process.pid), 'escape'));
        assert.equal(JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).name, 'project');
        assert.equal(fs.readFileSync(path.join(root, 'sibling', 'approved.txt'), 'utf8'), 'approved-read');
        denied(() => fs.writeFileSync(path.join(root, 'sibling', 'approved.txt'), 'overwrite'));
        fs.writeFileSync(path.join(root, 'approved-output', 'allowed-' + process.pid), 'ok');
        fs.writeFileSync('package-write-' + process.pid, 'ok');
        assert.equal(process.env.CAPLOCK_TEST_SECRET, undefined);
        assert.equal(process.env.CAPLOCK_UNLISTED_VALUE, undefined);
        assert.equal(process.env.HOME, '/home/caplock');
        assert.equal(process.env.TMP, '/tmp');
        assert.equal(process.env.TMPDIR, '/tmp');
        assert.equal(process.env.PATH, '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin');
        assert.equal(process.env.npm_lifecycle_event, 'postinstall');
        assert.equal(process.env.NODE_NO_WARNINGS, '1');
      `;
      const childScript = environmentChecks + `
        // This read must receive EOF, not merely the input bytes. libuv needs
        // shutdown(SHUT_WR) on the parent's socketpair after its write drains.
        assert.equal(require('node:fs').readFileSync(0, 'utf8'), 'pipe-input');
        console.log('child-started'); console.error('child-stderr');
      `;
      const parentScript = environmentChecks + `
        const child = require('node:child_process').spawnSync(process.execPath, ['-e', ${JSON.stringify(childScript)}], { input: 'pipe-input', encoding: 'utf8', timeout: 3000 });
        assert.equal(child.error, undefined);
        assert.equal(child.status, 0, child.stderr);
        assert.equal(child.stdout.trim(), 'child-started');
        assert.equal(child.stderr.trim(), 'child-stderr');
        console.log('parent-continued');
      `;
      for (const network of ["none", "host"] as const) {
        const nested = await backend.run({ executable: process.execPath, args: ["-e", parentScript], trustedExecutablePaths: [process.execPath] }, { ...policy, network, filesystem: { read: ["$PROJECT/sibling/approved.txt"], write: ["$PROJECT/approved-output"] } }, context);
        expect(nested.code, nested.stderr).toBe(0);
        expect(nested.stdout.trim()).toBe("parent-continued");
      }

      const server = net.createServer((socket) => { socket.on("error", () => undefined); socket.end("caplock\n"); });
      await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => resolve()); });
      const address = server.address(); if (!address || typeof address === "string") throw new Error("Could not start controlled localhost network endpoint");
      const script = "const n=require('node:net'),s=n.createConnection({host:'127.0.0.1',port:Number(process.argv[1])});s.once('connect',()=>{s.end();process.exit(0)});s.once('error',e=>process.exit(e.code==='EPERM'?2:4));setTimeout(()=>process.exit(3),3000)";
      try {
        const none = await backend.run({ executable: process.execPath, args: ["-e", script, String(address.port)], trustedExecutablePaths: [process.execPath] }, policy, context);
        expect(none.code, `seccomp must deny a real TCP connection with EPERM: ${none.stderr}`).toBe(2);
        const hostPolicy = { ...policy, network: "host" as const };
        const host = await backend.run({ executable: process.execPath, args: ["-e", script, String(address.port)], trustedExecutablePaths: [process.execPath] }, hostPolicy, context);
        expect(host.code, `network:host did not reach the controlled endpoint: ${host.stderr}`).toBe(0);
      } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }

      const udp = dgram.createSocket("udp4");
      udp.on("message", (message, peer) => udp.send(message, peer.port, peer.address));
      await new Promise<void>((resolve, reject) => { udp.once("error", reject); udp.bind(0, "127.0.0.1", resolve); });
      try {
        const udpScript = "const s=require('node:dgram').createSocket('udp4');s.once('message',()=>process.exit(0));s.once('error',e=>process.exit(e.code==='EPERM'?2:4));s.send('probe',Number(process.argv[1]),'127.0.0.1',e=>{if(e)process.exit(e.code==='EPERM'?2:4)});setTimeout(()=>process.exit(3),3000)";
        // Run the network probe in a default-pipe child too: seccomp must inherit.
        const nestedNetwork = "const r=require('node:child_process').spawnSync(process.execPath,['-e',process.argv[1],process.argv[2]],{timeout:4000});process.exit(r.error?5:r.status??6)";
        for (const network of ["none", "host"] as const) {
          const result = await backend.run({ executable: process.execPath, args: ["-e", nestedNetwork, udpScript, String(udp.address().port)], trustedExecutablePaths: [process.execPath] }, { ...policy, network }, context);
          expect(result.code, `nested UDP ${network}: ${result.stderr}`).toBe(network === "none" ? 2 : 0);
        }
      } finally { await new Promise<void>((resolve) => udp.close(resolve)); }
    } finally { vi.unstubAllEnvs(); rmSync(root, { recursive: true, force: true }); }
  });
});
