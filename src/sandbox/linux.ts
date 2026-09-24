import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import net from "node:net";
import path from "node:path";
import { filterEnvironment, substitutePolicyPath } from "../policy.js";
import { commandExists, run } from "../process.js";
import { redactText } from "../util.js";
import type { DoctorCheck, SandboxAvailability, SandboxBackend, SandboxCapabilities, SandboxCommand, SandboxContext, SandboxResult } from "../types.js";

const systemPaths = ["/usr", "/bin", "/lib", "/lib64", "/sbin", "/etc"];
const capabilities: SandboxCapabilities = { filesystemIsolation: true, environmentIsolation: true, networkIsolation: true, processContainment: true, processObservation: true };

/** Argument construction used by the production backend and its unit tests. */
export function buildLinuxArgs(command: SandboxCommand, policy: Required<import("../types.js").Policy>, context: SandboxContext): string[] {
  const args = ["--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-user", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/home", "--dir", "/home/caplock"];
  for (const item of systemPaths) if (existsSync(item)) args.push("--ro-bind", item, item);
  for (const item of ["package.json", "package-lock.json", "pnpm-lock.yaml", "node_modules"]) { const source = path.join(context.projectRoot, item); if (existsSync(source)) args.push("--ro-bind", source, source); }
  args.push("--bind", context.identity.packageDir, context.identity.packageDir);
  for (const item of policy.filesystem?.read ?? []) { const source = substitutePolicyPath(item, context.projectRoot, context.identity.packageDir, { home: "/home/caplock", tmp: "/tmp" }); if (existsSync(source)) args.push("--ro-bind", source, source); }
  for (const item of policy.filesystem?.write ?? []) { const source = substitutePolicyPath(item, context.projectRoot, context.identity.packageDir, { home: "/home/caplock", tmp: "/tmp" }); mkdirSync(source, { recursive: true }); args.push("--bind", source, source); }
  for (const [key, value] of Object.entries(filterEnvironment(context.childEnv ?? context.controlEnv ?? process.env, policy.env?.allow ?? []))) args.push("--setenv", key, value);
  if (policy.network === "none") args.push("--seccomp", "3");
  for (const executable of command.trustedExecutablePaths ?? []) if (existsSync(executable)) args.push("--ro-bind", executable, executable);
  args.push("--chdir", command.cwd ?? context.identity.packageDir, "--", command.executable, ...command.args);
  return args;
}

export function buildLinuxInvocation(command: SandboxCommand, policy: Required<import("../types.js").Policy>, context: SandboxContext): { executable: string; args: string[] } {
  return { executable: "bwrap", args: buildLinuxArgs(command, policy, context) };
}

// A seccomp-BPF filter denies network syscalls in the child tree without
// creating/configuring a network namespace. This works on hosted kernels that
// forbid RTM_NEWADDR while retaining kernel-enforced network denial.
function networkDenyFilter(): Buffer {
  const arch = process.arch === "arm64" ? 0xc00000b7 : 0xc000003e;
  if (process.arch !== "x64" && process.arch !== "arm64") throw new Error(`Linux network isolation is unsupported on ${process.arch}.`);
  const calls = process.arch === "arm64"
    ? [198, 203, 200, 201, 202, 206, 207, 210, 199, 211, 212, 242, 243, 269, 425, 426]
    : [41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 53, 288, 299, 307, 425, 426];
  const ins: Array<[number, number, number, number]> = [[0x20, 0, 0, 4], [0x15, 1, 0, arch], [0x06, 0, 0, 0x80000000], [0x20, 0, 0, 0]];
  for (const nr of [...new Set(calls)]) ins.push([0x15, 0, 1, nr], [0x06, 0, 0, 0x00050000 | 1]);
  ins.push([0x06, 0, 0, 0x7fff0000]);
  const bpf = Buffer.alloc(ins.length * 8);
  ins.forEach(([code, jt, jf, k], i) => { const offset = i * 8; bpf.writeUInt16LE(code, offset); bpf.writeUInt8(jt, offset + 2); bpf.writeUInt8(jf, offset + 3); bpf.writeUInt32LE(k >>> 0, offset + 4); });
  return bpf;
}

export class LinuxBubblewrapBackend implements SandboxBackend {
  readonly id = "linux-bubblewrap"; readonly platform = "linux" as const;
  async checkAvailability(): Promise<SandboxAvailability> {
    const available = await commandExists("bwrap") && (process.arch === "x64" || process.arch === "arm64");
    return { available, detail: available ? "bubblewrap and architecture-specific seccomp network isolation available" : "Install bubblewrap and use a supported Linux x64/arm64 runtime (for Debian/Ubuntu: sudo apt-get install bubblewrap strace).", capabilities };
  }
  async doctor(): Promise<DoctorCheck[]> {
    const bwrap = await this.checkAvailability(); const strace = await commandExists("strace");
    const checks: DoctorCheck[] = [{ name: "native Linux backend", ok: bwrap.available, detail: bwrap.detail }, { name: "strace observation", ok: strace, detail: strace ? "available" : "Install strace for execution observations." }];
    if (bwrap.available) {
      const root = mkdtempSync(path.join(os.tmpdir(), "caplock-linux-doctor-"));
      try {
        const packageDir = path.join(root, "node_modules", "probe"); mkdirSync(packageDir, { recursive: true }); writeFileSync(path.join(packageDir, "package.json"), '{"name":"probe","version":"1.0.0"}');
        const policy: Required<import("../types.js").Policy> = { filesystem: { read: [], write: [] }, env: { allow: [] }, network: "none" };
        const identity = { name: "probe", version: "1.0.0", packageDir, packageJsonPath: path.join(packageDir, "package.json") };
        const context = { projectRoot: root, identity, childEnv: { ...process.env, CAPLOCK_TEST_SECRET: "CAPLOCK_SECRET_DO_NOT_LEAK" }, timeoutMs: 15_000 };
        const probe = await this.run({ executable: "/bin/sh", args: ["-c", "test \"$HOME\" = /home/caplock && test -z \"$CAPLOCK_TEST_SECRET\" && echo ok > package-write" ] }, policy, context);
        checks.push({ name: "Linux production filesystem/environment contract", ok: probe.code === 0 && existsSync(path.join(packageDir, "package-write")), detail: probe.code === 0 ? "active LinuxSandboxBackend filesystem/environment probe passed" : `contract probe failed: ${redactText(probe.stderr.trim())}` });
        const server = net.createServer((socket) => socket.end("caplock\n"));
        await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => resolve()); });
        const address = server.address();
        if (!address || typeof address === "string") throw new Error("Could not start the controlled Linux network probe endpoint.");
        const script = "const n=require('node:net'),s=n.createConnection({host:'127.0.0.1',port:Number(process.argv[1])});s.once('connect',()=>{s.end();process.exit(0)});s.once('error',()=>process.exit(2));setTimeout(()=>process.exit(3),3000)";
        try {
          const none = await this.run({ executable: process.execPath, args: ["-e", script, String(address.port)], trustedExecutablePaths: [process.execPath] }, policy, context);
          const hostPolicy = { ...policy, network: "host" as const };
          const host = await this.run({ executable: process.execPath, args: ["-e", script, String(address.port)], trustedExecutablePaths: [process.execPath] }, hostPolicy, context);
          checks.push({ name: "network.default-deny", ok: none.code !== 0, detail: none.code !== 0 ? "sandboxed TCP connection was denied by seccomp" : "sandbox unexpectedly connected to controlled endpoint" });
          checks.push({ name: "network.host-allow", ok: host.code === 0, detail: host.code === 0 ? "same sandboxed TCP connection reached controlled endpoint" : `network:host failed (exit=${host.code}): ${redactText(host.stderr.trim())}` });
        } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
      } finally { rmSync(root, { recursive: true, force: true }); }
    }
    return checks;
  }
  async run(command: SandboxCommand, policy: Required<import("../types.js").Policy>, context: SandboxContext): Promise<SandboxResult> {
    const availability = await this.checkAvailability(); if (!availability.available) throw new Error(availability.detail);
    const invocation = buildLinuxInvocation(command, policy, context);
    if (policy.network !== "none") return run(invocation.executable, invocation.args, { timeoutMs: context.timeoutMs });
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-seccomp-")); const filter = path.join(root, "network-deny.bpf");
    let fd: number | undefined;
    try {
      writeFileSync(filter, networkDenyFilter(), { mode: 0o600 }); fd = openSync(filter, "r");
      const pending = run(invocation.executable, invocation.args, { timeoutMs: context.timeoutMs, passFds: [fd] });
      closeSync(fd); fd = undefined;
      return await pending;
    } finally { if (fd !== undefined) closeSync(fd); rmSync(root, { recursive: true, force: true }); }
  }
}
