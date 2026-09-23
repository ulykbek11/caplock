import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { filterEnvironment, substitutePolicyPath } from "../policy.js";
import { run } from "../process.js";
import { isWithin, realpathOrResolve } from "../util.js";
import type { DoctorCheck, SandboxAvailability, SandboxBackend, SandboxCapabilities, SandboxCommand, SandboxContext, SandboxResult } from "../types.js";

const capabilities: SandboxCapabilities = { filesystemIsolation: true, environmentIsolation: true, networkIsolation: true, processContainment: true, processObservation: false };
function helperPath(): string { return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../native/bin/caplock-sandbox.exe"); }

/** AppContainer helper is always resolved by absolute path, never from PATH. */
export class WindowsSandboxBackend implements SandboxBackend {
  readonly id = "windows-native"; readonly platform = "win32" as const;
  async checkAvailability(): Promise<SandboxAvailability> {
    const available = existsSync(helperPath());
    return { available, detail: available ? "native AppContainer helper available" : "Native helper is missing. Run npm run native:build from a Visual Studio developer prompt.", capabilities };
  }
  async doctor(): Promise<DoctorCheck[]> {
    const helper = await this.checkAvailability();
    const checks: DoctorCheck[] = [{ name: "native Windows backend", ok: helper.available, detail: helper.detail }];
    if (!helper.available) return checks;
    const probe = await run(helperPath(), ["--selftest"], { timeoutMs: 30_000 });
    let result: Record<string, unknown> | undefined;
    try { result = JSON.parse(probe.stdout.trim()) as Record<string, unknown>; } catch { /* reported below */ }
    const passed = (key: string): boolean => probe.code === 0 && result?.[key] === true;
    checks.push(
      { name: "sandbox.process-launch", ok: passed("processLaunched"), detail: passed("processLaunched") ? "active AppContainer launch passed" : "native selftest failed" },
      { name: "sandbox.token-is-appcontainer", ok: passed("tokenIsAppContainer"), detail: passed("tokenIsAppContainer") ? "child token verified" : "native selftest failed" },
      { name: "filesystem.package-write", ok: passed("allowedWrite"), detail: passed("allowedWrite") ? "AppContainer ACL write probe passed" : "native selftest failed" },
      { name: "sandbox.cleanup", ok: passed("cleanup"), detail: passed("cleanup") ? "temporary profile and fixture cleaned" : "native selftest failed" },
      { name: "network.default-deny", ok: false, detail: "requires the full Windows security contract probe" },
    );
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-doctor-"));
    try {
      const packageDir = path.join(root, "package"); const sibling = path.join(root, "sibling"); const temp = path.join(root, "temp");
      mkdirSync(packageDir); mkdirSync(sibling); mkdirSync(temp); writeFileSync(path.join(root, ".env"), "CAPLOCK_DOCTOR_SECRET=not-a-real-secret"); writeFileSync(path.join(root, "source.txt"), "protected");
      const cmd = process.env.ComSpec ?? path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "cmd.exe");
      const probe = async (text: string): Promise<number> => (await run(helperPath(), ["--package", packageDir, "--temp", temp, "--cwd", packageDir, "--network", "none", "--", cmd, "/d", "/s", "/c", text], { env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, ComSpec: cmd, CAPLOCK_TEST_SECRET: "CAPLOCK_SECRET_SHOULD_NOT_LEAK_7391" }, timeoutMs: 20_000 })).code;
      const packageWrite = await probe("echo allowed> package-write.txt");
      const projectRead = await probe(`type "${path.join(root, ".env")}"`);
      const projectWrite = await probe(`echo denied> "${path.join(root, "source.txt")}"`);
      const siblingWrite = await probe(`echo denied> "${path.join(sibling, "x.txt")}"`);
      const envLeak = await probe("if defined CAPLOCK_TEST_SECRET exit /b 9");
      checks.push(
        { name: "filesystem.package-write", ok: packageWrite === 0 && existsSync(path.join(packageDir, "package-write.txt")), detail: "active package ACL probe" },
        { name: "filesystem.project-secret-denied", ok: projectRead !== 0, detail: "active synthetic .env probe" },
        { name: "filesystem.project-write-denied", ok: projectWrite !== 0 && readFileSync(path.join(root, "source.txt"), "utf8") === "protected", detail: "active protected project write probe" },
        { name: "filesystem.sibling-write-denied", ok: siblingWrite !== 0 && !existsSync(path.join(sibling, "x.txt")), detail: "active sibling write probe" },
        { name: "environment.secret-hidden", ok: envLeak === 0, detail: "active synthetic secret environment probe" },
      );
    } catch (error) { checks.push({ name: "Windows filesystem/environment contract", ok: false, detail: error instanceof Error ? error.message : "probe failed" }); }
    finally { rmSync(root, { recursive: true, force: true }); }
    return checks;
  }
  async run(command: SandboxCommand, policy: Required<import("../types.js").Policy>, context: SandboxContext): Promise<SandboxResult> {
    const availability = await this.checkAvailability(); if (!availability.available) throw new Error(availability.detail);
    mkdirSync(path.join(os.tmpdir(), "caplock"), { recursive: true, mode: 0o700 });
    const sandboxRoot = mkdtempSync(path.join(os.tmpdir(), "caplock", "run-"));
    const home = path.join(sandboxRoot, "home"); mkdirSync(home, { recursive: true, mode: 0o700 });
    const env = filterEnvironment(process.env, policy.env?.allow ?? []);
    Object.assign(env, { USERPROFILE: home, HOME: home, HOMEDRIVE: path.parse(home).root.slice(0, 2), HOMEPATH: home.slice(path.parse(home).root.length - 1), TEMP: home, TMP: home });
    const packageDir = realpathOrResolve(context.identity.packageDir);
    const cwd = realpathOrResolve(command.cwd ?? packageDir);
    if (!isWithin(cwd, packageDir)) throw new Error("Sandbox working directory must remain within the package.");
    const resolveGrant = (item: string): string => {
      const resolved = realpathOrResolve(substitutePolicyPath(item, context.projectRoot, packageDir, { home, tmp: sandboxRoot }));
      const root = item.startsWith("$PACKAGE/") ? packageDir : item.startsWith("$PROJECT/") ? realpathOrResolve(context.projectRoot) : item.startsWith("$HOME/") ? home : sandboxRoot;
      if (!isWithin(resolved, root)) throw new Error(`Policy grant resolves outside its allowed root: ${item}`);
      return resolved;
    };
    const reads = (policy.filesystem?.read ?? []).map(resolveGrant);
    const writes = (policy.filesystem?.write ?? []).map(resolveGrant);
    for (const target of writes) mkdirSync(target, { recursive: true, mode: 0o700 });
    const args = ["--package", packageDir, "--temp", sandboxRoot, "--cwd", cwd, "--network", policy.network, ...reads.flatMap((item) => ["--read", item]), ...writes.flatMap((item) => ["--write", item]), "--", command.executable, ...command.args];
    try { return await run(helperPath(), args, { env, timeoutMs: context.timeoutMs }); } finally { rmSync(sandboxRoot, { recursive: true, force: true }); }
  }
}
