import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { filterEnvironment, substitutePolicyPath } from "../policy.js";
import { commandExists, run } from "../process.js";
import type { DoctorCheck, SandboxAvailability, SandboxBackend, SandboxCapabilities, SandboxCommand, SandboxContext, SandboxResult } from "../types.js";

const systemPaths = ["/usr", "/bin", "/lib", "/lib64", "/sbin", "/etc"];
const capabilities: SandboxCapabilities = { filesystemIsolation: true, environmentIsolation: true, networkIsolation: true, processContainment: true, processObservation: true };
export class LinuxBubblewrapBackend implements SandboxBackend {
  readonly id = "linux-bubblewrap"; readonly platform = "linux" as const;
  async checkAvailability(): Promise<SandboxAvailability> {
    const available = await commandExists("bwrap");
    return { available, detail: available ? "bubblewrap available" : "Install bubblewrap (for Debian/Ubuntu: sudo apt-get install bubblewrap strace).", capabilities };
  }
  async doctor(): Promise<DoctorCheck[]> {
    const bwrap = await this.checkAvailability(); const strace = await commandExists("strace");
    const checks: DoctorCheck[] = [{ name: "native Linux backend", ok: bwrap.available, detail: bwrap.detail }, { name: "strace observation", ok: strace, detail: strace ? "available" : "Install strace for execution observations." }];
    if (bwrap.available) { const probe = await run("bwrap", ["--unshare-user", "--unshare-net", "--ro-bind", "/usr", "/usr", "--proc", "/proc", "/bin/true"]); checks.push({ name: "user and network namespaces", ok: probe.code === 0, detail: probe.code === 0 ? "active probe passed" : "Bubblewrap could not create namespaces." }); }
    return checks;
  }
  async run(command: SandboxCommand, policy: Required<import("../types.js").Policy>, context: SandboxContext): Promise<SandboxResult> {
    const availability = await this.checkAvailability(); if (!availability.available) throw new Error(availability.detail);
    const args = ["--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-user", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/home", "--dir", "/home/caplock"];
    if (policy.network === "none") args.push("--unshare-net");
    for (const item of systemPaths) if (existsSync(item)) args.push("--ro-bind", item, item);
    for (const item of ["package.json", "package-lock.json", "pnpm-lock.yaml", "node_modules"]) { const source = path.join(context.projectRoot, item); if (existsSync(source)) args.push("--ro-bind", source, source); }
    args.push("--bind", context.identity.packageDir, context.identity.packageDir);
    for (const item of policy.filesystem?.read ?? []) { const source = substitutePolicyPath(item, context.projectRoot, context.identity.packageDir, { home: "/home/caplock", tmp: "/tmp" }); if (existsSync(source)) args.push("--ro-bind", source, source); }
    for (const item of policy.filesystem?.write ?? []) { const source = substitutePolicyPath(item, context.projectRoot, context.identity.packageDir, { home: "/home/caplock", tmp: "/tmp" }); mkdirSync(source, { recursive: true }); args.push("--bind", source, source); }
    for (const [key, value] of Object.entries(filterEnvironment(process.env, policy.env?.allow ?? []))) args.push("--setenv", key, value);
    args.push("--chdir", command.cwd ?? context.identity.packageDir, "--", command.executable, ...command.args);
    return run("bwrap", args, { timeoutMs: context.timeoutMs });
  }
}
