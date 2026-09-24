import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
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
      writeFileSync(profile, "(version 1) (deny default) (allow process-exec) (allow process-fork) (allow file-read* (subpath \"/usr\") (subpath \"/System\") (subpath \"/bin\") (subpath \"/sbin\"))");
      const probe = await run("sandbox-exec", ["-f", profile, "/bin/true"], { timeoutMs: 15_000 });
      const checks: DoctorCheck[] = [{ name: "native macOS backend", ok: probe.code === 0, detail: probe.code === 0 ? "active Seatbelt launch passed" : `Seatbelt launch probe failed (exit=${probe.code}): ${redactText(probe.stderr.trim() || probe.stdout.trim() || "sandbox-exec returned no diagnostic")}` }];
      if (probe.code === 0) {
        const packageDir = path.join(temp, "package"); mkdirSync(packageDir); writeFileSync(path.join(packageDir, "package.json"), '{"name":"probe","version":"1.0.0"}');
        const contract = await this.run({ executable: "/bin/sh", args: ["-c", "test -z \"$CAPLOCK_TEST_SECRET\" && echo ok > package-write && ! /usr/bin/nc -zw1 1.1.1.1 53"] }, { filesystem: { read: [], write: [] }, env: { allow: [] }, network: "none" }, { projectRoot: temp, identity: { name: "probe", version: "1.0.0", packageDir, packageJsonPath: path.join(packageDir, "package.json") }, timeoutMs: 15_000 });
        checks.push({ name: "macOS production filesystem/environment/network:none contract", ok: contract.code === 0, detail: contract.code === 0 ? "active MacOSSandboxBackend probe passed" : `Seatbelt contract probe failed: ${redactText(contract.stderr.trim())}` });
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
    const lines = ["(version 1)", "(deny default)", "(allow process-exec)", "(allow process-fork)", "(allow file-read* (subpath \"/usr\") (subpath \"/System\") (subpath \"/bin\") (subpath \"/sbin\"))"];
    for (const item of read) lines.push(`(allow file-read* (subpath ${quote(item)}))`);
    for (const item of write) lines.push(`(allow file-read* file-write* (subpath ${quote(item)}))`);
    if (policy.network === "host") lines.push("(allow network*)");
    const profile = path.join(root, "caplock.sb"); writeFileSync(profile, lines.join("\n"), { mode: 0o600 });
    const env = filterEnvironment(context.childEnv ?? context.controlEnv ?? process.env, policy.env?.allow ?? []); Object.assign(env, { HOME: home, TMPDIR: tmp, TMP: tmp });
    try { return await run("sandbox-exec", ["-f", profile, command.executable, ...command.args], { cwd: canonicalPath(command.cwd ?? context.identity.packageDir), env, timeoutMs: context.timeoutMs }); }
    finally { rmSync(root, { recursive: true, force: true }); }
  }
}
