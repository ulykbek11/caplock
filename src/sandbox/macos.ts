import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import net from "node:net";
import path from "node:path";
import { filterEnvironment, substitutePolicyPath } from "../policy.js";
import { commandExists, run } from "../process.js";
import { redactText } from "../util.js";
import type { DoctorCheck, SandboxAvailability, SandboxBackend, SandboxCapabilities, SandboxCommand, SandboxContext, SandboxResult } from "../types.js";
const capabilities: SandboxCapabilities = { filesystemIsolation: true, environmentIsolation: true, networkIsolation: true, processContainment: true, processObservation: false };
const quote = (value: string): string => `"${value.replaceAll("\\", "\\\\").replaceAll('"', "\\\"")}"`;
function canonicalPath(value: string): string {
  const resolved = path.resolve(value); let cursor = resolved; const suffix: string[] = [];
  while (!existsSync(cursor)) {
    const parent = path.dirname(cursor); if (parent === cursor) return resolved;
    suffix.unshift(path.basename(cursor)); cursor = parent;
  }
  try { return path.join(realpathSync.native(cursor), ...suffix); } catch { return resolved; }
}
/** sandbox-exec/Seatbelt is deprecated but remains Apple's practical user-space sandbox launcher. */
export class MacOSSandboxBackend implements SandboxBackend {
  readonly id = "macos-native"; readonly platform = "darwin" as const;
  async checkAvailability(): Promise<SandboxAvailability> { const available = await commandExists("sandbox-exec"); return { available, detail: available ? "sandbox-exec available" : "sandbox-exec is unavailable; CapLock will not run scripts unrestricted.", capabilities }; }
  async doctor(): Promise<DoctorCheck[]> {
    const availability = await this.checkAvailability();
    if (!availability.available) return [{ name: "native macOS backend", ok: false, detail: availability.detail }];
    const temp = mkdtempSync(path.join(os.tmpdir(), "caplock-seatbelt-"));
    try {
      const profile = path.join(temp, "probe.sb");
      const systemPaths = ["/usr", "/System", "/bin", "/sbin"];
      writeFileSync(profile, ["(version 1)", "(deny default)", '(import "bsd.sb")', "(allow process-fork)", `(allow process-exec (literal ${quote("/usr/bin/true")}))`, ...systemPaths.map((p) => `(allow process-exec (subpath ${quote(p)}))`), ...systemPaths.map((p) => `(allow file-read* (subpath ${quote(p)}))`)].join("\n"));
      const probe = await run("sandbox-exec", ["-f", profile, "/usr/bin/true"], { timeoutMs: 15_000 });
      const checks: DoctorCheck[] = [{ name: "native macOS backend", ok: probe.code === 0, detail: probe.code === 0 ? "active Seatbelt launch passed" : `Seatbelt launch probe failed (exit=${probe.code}): ${redactText(probe.stderr.trim() || probe.stdout.trim() || "sandbox-exec returned no diagnostic")}` }];
      if (probe.code === 0) {
        const packageDir = path.join(temp, "package"); mkdirSync(packageDir); writeFileSync(path.join(packageDir, "package.json"), '{"name":"probe","version":"1.0.0"}');
        const policy: Required<import("../types.js").Policy> = { filesystem: { read: [], write: [] }, env: { allow: [] }, network: "none" };
        const identity = { name: "probe", version: "1.0.0", packageDir, packageJsonPath: path.join(packageDir, "package.json") };
        const context = { projectRoot: temp, identity, childEnv: { ...process.env, CAPLOCK_TEST_SECRET: "CAPLOCK_SECRET_DO_NOT_LEAK" }, timeoutMs: 15_000 };
        const contract = await this.run({ executable: "/bin/sh", args: ["-c", "test -z \"$CAPLOCK_TEST_SECRET\" && echo ok > package-write"] }, policy, context);
        checks.push({ name: "macOS production filesystem/environment/network:none contract", ok: contract.code === 0, detail: contract.code === 0 ? "active MacOSSandboxBackend probe passed" : `Seatbelt contract probe failed: ${redactText(contract.stderr.trim())}` });
        const server = net.createServer((socket) => { socket.on("error", () => undefined); socket.end("caplock\n"); });
        await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => resolve()); });
        const address = server.address();
        if (!address || typeof address === "string") throw new Error("Could not start the controlled macOS network probe endpoint.");
        const script = "const n=require('node:net'),s=n.createConnection({host:'127.0.0.1',port:Number(process.argv[1])});s.once('connect',()=>{s.end();process.exit(0)});s.once('error',()=>process.exit(2));setTimeout(()=>process.exit(3),3000)";
        try {
          const none = await this.run({ executable: process.execPath, args: ["-e", script, String(address.port)], trustedExecutablePaths: [process.execPath] }, policy, context);
          const hostPolicy = { ...policy, network: "host" as const };
          const host = await this.run({ executable: process.execPath, args: ["-e", script, String(address.port)], trustedExecutablePaths: [process.execPath] }, hostPolicy, context);
          checks.push({ name: "network.default-deny", ok: none.code !== 0, detail: none.code !== 0 ? "Seatbelt denied connection to controlled endpoint" : "sandbox unexpectedly connected to controlled endpoint" });
          checks.push({ name: "network.host-allow", ok: host.code === 0, detail: host.code === 0 ? "network:host reached controlled endpoint" : `network:host failed (exit=${host.code}): ${redactText(host.stderr.trim())}` });
        } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
      }
      return checks;
    } finally { rmSync(temp, { recursive: true, force: true }); }
  }
  async run(command: SandboxCommand, policy: Required<import("../types.js").Policy>, context: SandboxContext): Promise<SandboxResult> {
    const availability = await this.checkAvailability(); if (!availability.available) throw new Error(availability.detail);
    const root = canonicalPath(mkdtempSync(path.join(os.tmpdir(), "caplock-seatbelt-"))); const home = path.join(root, "home"); const tmp = path.join(root, "tmp"); mkdirSync(home); mkdirSync(tmp);
    const dynamic = { home, tmp };
    const packageDir = canonicalPath(context.identity.packageDir);
    const read = [packageDir, ...(policy.filesystem?.read ?? []).map((p) => canonicalPath(substitutePolicyPath(p, context.projectRoot, context.identity.packageDir, dynamic)))];
    const write = [packageDir, tmp, home, ...(policy.filesystem?.write ?? []).map((p) => canonicalPath(substitutePolicyPath(p, context.projectRoot, context.identity.packageDir, dynamic)))];
    // Never grant /private wholesale: it contains users' temporary files and
    // application data on macOS. The standard executable and library roots
    // below are sufficient for the supported shell/Node invocation.
    const executableRoots = ["/usr", "/System", "/bin", "/sbin"];
    // Apple's bsd.sb is the narrow runtime baseline needed by ordinary
    // executables (dyld, shared libraries, and basic kernel queries). Without
    // it even a permitted /usr/bin/true can exit 1 before user code starts.
    // It does not grant arbitrary project/home access or networking; those
    // remain controlled by the explicit rules below and network policy.
    const lines = ["(version 1)", "(deny default)", '(import "bsd.sb")', "(allow process-fork)", ...executableRoots.map((item) => `(allow process-exec (subpath ${quote(item)}))`), ...executableRoots.map((item) => `(allow file-read* (subpath ${quote(item)}))`)];
    const commandExecutable = path.isAbsolute(command.executable) ? canonicalPath(command.executable) : undefined;
    if (commandExecutable) lines.push(`(allow process-exec (literal ${quote(commandExecutable)}))`);
    for (const item of read) lines.push(`(allow file-read* (subpath ${quote(item)}))`);
    for (const item of write) lines.push(`(allow file-read* file-write* (subpath ${quote(item)}))`);
    for (const item of command.trustedExecutablePaths ?? []) {
      const executable = canonicalPath(item);
      lines.push(`(allow file-read* (literal ${quote(executable)}))`);
      lines.push(`(allow process-exec (literal ${quote(executable)}))`);
      // macOS requires search permission on each directory while resolving an
      // executable path. Metadata-only grants permit traversal without making
      // adjacent toolchain files readable.
      for (let parent = path.dirname(executable); parent !== "/"; parent = path.dirname(parent)) lines.push(`(allow file-read-metadata (literal ${quote(parent)}))`);
    }
    if (policy.network === "host") lines.push("(allow network*)");
    const profile = path.join(root, "caplock.sb"); writeFileSync(profile, lines.join("\n"), { mode: 0o600 });
    if (process.env.CAPLOCK_DEBUG === "1") console.error(`CapLock Seatbelt profile (${profile}):\n${lines.join("\n")}`);
    const env = filterEnvironment(context.childEnv ?? context.controlEnv ?? process.env, policy.env?.allow ?? []); Object.assign(env, { HOME: home, TMPDIR: tmp, TMP: tmp });
    try {
      const result = await run("sandbox-exec", ["-f", profile, command.executable, ...command.args], { cwd: canonicalPath(command.cwd ?? context.identity.packageDir), env, timeoutMs: context.timeoutMs });
      if (result.code !== 0 && process.env.CAPLOCK_DEBUG === "1") {
        const diagnostic = `CapLock Seatbelt child failed: exit=${result.code}; cwd=${canonicalPath(command.cwd ?? context.identity.packageDir)}; executable=${command.executable}; profile=${lines.join(" | ")}; stderr=${redactText(result.stderr.trim())}`;
        console.error(diagnostic);
        result.stderr = `${result.stderr}${result.stderr ? "\n" : ""}${diagnostic}`;
      }
      return result;
    }
    finally { rmSync(root, { recursive: true, force: true }); }
  }
}
