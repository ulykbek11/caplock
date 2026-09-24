import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { filterEnvironment, substitutePolicyPath } from "../policy.js";
import { commandExists, run } from "../process.js";
import { redactText } from "../util.js";
import type { DoctorCheck, SandboxAvailability, SandboxBackend, SandboxCapabilities, SandboxCommand, SandboxContext, SandboxResult } from "../types.js";

const systemPaths = ["/usr", "/bin", "/lib", "/lib64", "/sbin", "/etc"];
const capabilities: SandboxCapabilities = { filesystemIsolation: true, environmentIsolation: true, networkIsolation: true, processContainment: true, processObservation: true };

/** Argument construction used by the production backend and its unit tests. */
export function buildLinuxArgs(command: SandboxCommand, policy: Required<import("../types.js").Policy>, context: SandboxContext): string[] {
  const args = ["--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/home", "--dir", "/home/caplock", "--share-net"];
  // The network namespace is created by util-linux `unshare` for network:none
  // (see buildLinuxInvocation). This keeps Bubblewrap from attempting a
  // RTM_NEWADDR loopback configuration that hosted runners may forbid; the
  // fresh namespace still has no usable interfaces or routes.
  if (policy.network === "host") args.splice(2, 0, "--unshare-user");
  for (const item of systemPaths) if (existsSync(item)) args.push("--ro-bind", item, item);
  for (const item of ["package.json", "package-lock.json", "pnpm-lock.yaml", "node_modules"]) { const source = path.join(context.projectRoot, item); if (existsSync(source)) args.push("--ro-bind", source, source); }
  args.push("--bind", context.identity.packageDir, context.identity.packageDir);
  for (const item of policy.filesystem?.read ?? []) { const source = substitutePolicyPath(item, context.projectRoot, context.identity.packageDir, { home: "/home/caplock", tmp: "/tmp" }); if (existsSync(source)) args.push("--ro-bind", source, source); }
  for (const item of policy.filesystem?.write ?? []) { const source = substitutePolicyPath(item, context.projectRoot, context.identity.packageDir, { home: "/home/caplock", tmp: "/tmp" }); mkdirSync(source, { recursive: true }); args.push("--bind", source, source); }
  for (const [key, value] of Object.entries(filterEnvironment(context.childEnv ?? context.controlEnv ?? process.env, policy.env?.allow ?? []))) args.push("--setenv", key, value);
  args.push("--chdir", command.cwd ?? context.identity.packageDir, "--", command.executable, ...command.args);
  return args;
}

export function buildLinuxInvocation(command: SandboxCommand, policy: Required<import("../types.js").Policy>, context: SandboxContext): { executable: string; args: string[] } {
  const bubblewrapArgs = buildLinuxArgs(command, policy, context);
  if (policy.network === "host") return { executable: "bwrap", args: bubblewrapArgs };
  return { executable: "unshare", args: ["--user", "--map-root-user", "--net", "--", "bwrap", ...bubblewrapArgs] };
}

export class LinuxBubblewrapBackend implements SandboxBackend {
  readonly id = "linux-bubblewrap"; readonly platform = "linux" as const;
  async checkAvailability(): Promise<SandboxAvailability> {
    const available = await commandExists("bwrap") && await commandExists("unshare");
    return { available, detail: available ? "bubblewrap and util-linux unshare available" : "Install bubblewrap and util-linux unshare (for Debian/Ubuntu: sudo apt-get install bubblewrap util-linux strace).", capabilities };
  }
  async doctor(): Promise<DoctorCheck[]> {
    const bwrap = await this.checkAvailability(); const strace = await commandExists("strace");
    const checks: DoctorCheck[] = [{ name: "native Linux backend", ok: bwrap.available, detail: bwrap.detail }, { name: "strace observation", ok: strace, detail: strace ? "available" : "Install strace for execution observations." }];
    if (bwrap.available) {
      const root = mkdtempSync(path.join(os.tmpdir(), "caplock-linux-doctor-"));
      try {
        const packageDir = path.join(root, "node_modules", "probe"); mkdirSync(packageDir, { recursive: true }); writeFileSync(path.join(packageDir, "package.json"), '{"name":"probe","version":"1.0.0"}');
        const policy: Required<import("../types.js").Policy> = { filesystem: { read: [], write: [] }, env: { allow: [] }, network: "none" };
        const probe = await this.run({ executable: "/bin/sh", args: ["-c", "test \"$HOME\" = /home/caplock && test -z \"$CAPLOCK_TEST_SECRET\" && echo ok > package-write && ! getent hosts example.com" ] }, policy, { projectRoot: root, identity: { name: "probe", version: "1.0.0", packageDir, packageJsonPath: path.join(packageDir, "package.json") }, timeoutMs: 15_000 });
        checks.push({ name: "Linux production filesystem/environment/network:none contract", ok: probe.code === 0 && existsSync(path.join(packageDir, "package-write")), detail: probe.code === 0 ? "active LinuxSandboxBackend probe passed" : `contract probe failed: ${redactText(probe.stderr.trim())}` });
      } finally { rmSync(root, { recursive: true, force: true }); }
    }
    return checks;
  }
  async run(command: SandboxCommand, policy: Required<import("../types.js").Policy>, context: SandboxContext): Promise<SandboxResult> {
    const availability = await this.checkAvailability(); if (!availability.available) throw new Error(availability.detail);
    const invocation = buildLinuxInvocation(command, policy, context);
    return run(invocation.executable, invocation.args, { timeoutMs: context.timeoutMs });
  }
}
