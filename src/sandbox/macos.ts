import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { filterEnvironment, substitutePolicyPath } from "../policy.js";
import { commandExists, run } from "../process.js";
import type { DoctorCheck, SandboxAvailability, SandboxBackend, SandboxCapabilities, SandboxCommand, SandboxContext, SandboxResult } from "../types.js";
const capabilities: SandboxCapabilities = { filesystemIsolation: true, environmentIsolation: true, networkIsolation: true, processContainment: true, processObservation: false };
const quote = (value: string): string => `"${value.replaceAll("\\", "\\\\").replaceAll('"', "\\\"")}"`;
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
      writeFileSync(profile, "(version 1) (deny default) (allow process-exec) (allow process-fork) (allow file-read* (literal \"/bin/true\"))");
      const probe = await run("sandbox-exec", ["-f", profile, "/bin/true"], { timeoutMs: 15_000 });
      return [{ name: "native macOS backend", ok: probe.code === 0, detail: probe.code === 0 ? "active Seatbelt launch passed" : "Seatbelt launch probe failed" }, { name: "sandbox.network", ok: false, detail: "full macOS security contract has not yet been verified" }];
    } finally { rmSync(temp, { recursive: true, force: true }); }
  }
  async run(command: SandboxCommand, policy: Required<import("../types.js").Policy>, context: SandboxContext): Promise<SandboxResult> {
    const availability = await this.checkAvailability(); if (!availability.available) throw new Error(availability.detail);
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-seatbelt-")); const home = path.join(root, "home"); const tmp = path.join(root, "tmp"); mkdirSync(home); mkdirSync(tmp);
    const dynamic = { home, tmp };
    const read = [context.identity.packageDir, ...(policy.filesystem?.read ?? []).map((p) => substitutePolicyPath(p, context.projectRoot, context.identity.packageDir, dynamic))];
    const write = [context.identity.packageDir, tmp, home, ...(policy.filesystem?.write ?? []).map((p) => substitutePolicyPath(p, context.projectRoot, context.identity.packageDir, dynamic))];
    const lines = ["(version 1)", "(deny default)", "(allow process-exec)", "(allow process-fork)", "(allow file-read* (subpath \"/usr\") (subpath \"/System\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/private\"))"];
    for (const item of read) lines.push(`(allow file-read* (subpath ${quote(item)}))`);
    for (const item of write) lines.push(`(allow file-read* file-write* (subpath ${quote(item)}))`);
    if (policy.network === "host") lines.push("(allow network*)");
    const profile = path.join(root, "caplock.sb"); writeFileSync(profile, lines.join("\n"), { mode: 0o600 });
    const env = filterEnvironment(process.env, policy.env?.allow ?? []); Object.assign(env, { HOME: home, TMPDIR: tmp, TMP: tmp });
    try { return await run("sandbox-exec", ["-f", profile, command.executable, ...command.args], { cwd: command.cwd ?? context.identity.packageDir, env, timeoutMs: context.timeoutMs }); }
    finally { rmSync(root, { recursive: true, force: true }); }
  }
}
