import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { filterEnvironment, substitutePolicyPath } from "../policy.js";
import { run } from "../process.js";
import { isWithin, realpathOrResolve } from "../util.js";
import { redactText } from "../util.js";
import type { DoctorCheck, SandboxAvailability, SandboxBackend, SandboxCapabilities, SandboxCommand, SandboxContext, SandboxResult } from "../types.js";

const capabilities: SandboxCapabilities = { filesystemIsolation: true, environmentIsolation: true, networkIsolation: true, processContainment: true, processObservation: false };
function helperPath(): string { return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../native/bin/caplock-sandbox.exe"); }

/** CreateProcessW requires one NUL after every entry and one extra final NUL. */
export function serializeWindowsEnvironment(env: Record<string, string>): Buffer {
  const entries = Object.entries(env).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => {
    if (!key || key.includes("=") || value.includes("\0")) throw new Error("Invalid Windows child environment entry");
    return `${key}=${value}\0`;
  });
  return Buffer.from(entries.join("") + "\0", "utf16le");
}

/** AppContainer helper is always resolved by absolute path, never from PATH. */
export class WindowsSandboxBackend implements SandboxBackend {
  readonly id = "windows-native"; readonly platform = "win32" as const;
  async checkAvailability(): Promise<SandboxAvailability> {
    if (process.arch !== "x64") return { available: false, detail: `Windows ${process.arch} is unsupported: CapLock v1 ships an x64 AppContainer helper.`, capabilities };
    if (!existsSync(helperPath())) return { available: false, detail: "Native helper is missing. Run npm run native:build from a Visual Studio developer prompt.", capabilities };
    // A present PE file is not a security capability. Verify the actual
    // AppContainer creation/token/ACL path before allowing any lifecycle.
    const selftest = await run(helperPath(), ["--selftest"], { timeoutMs: 30_000 });
    let result: Record<string, unknown> | undefined;
    try { result = JSON.parse(selftest.stdout.trim()) as Record<string, unknown>; } catch { /* diagnostics below */ }
    const available = selftest.code === 0 && result?.profileCreated === true && result?.processLaunched === true && result?.tokenIsAppContainer === true && result?.allowedWrite === true && result?.cleanup === true;
    return { available, detail: available ? "native AppContainer helper and active containment probe available" : `Native AppContainer preflight failed: ${redactText(selftest.stderr.trim() || "selftest did not satisfy the containment contract")}`, capabilities };
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
    );
    const root = mkdtempSync(path.join(os.tmpdir(), "caplock-doctor-"));
    try {
      const packageDir = path.join(root, "package"); const sibling = path.join(root, "sibling");
      mkdirSync(packageDir); mkdirSync(sibling); writeFileSync(path.join(root, ".env"), "CAPLOCK_DOCTOR_SECRET=not-a-real-secret"); writeFileSync(path.join(root, "source.txt"), "protected"); writeFileSync(path.join(packageDir, "package.json"), '{"name":"probe","version":"1.0.0"}');
      const probeChild = path.join(packageDir, "caplock-probe.exe"); copyFileSync(helperPath(), probeChild);
      const cmd = process.env.ComSpec ?? path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "cmd.exe");
      const policy: Required<import("../types.js").Policy> = { filesystem: { read: [], write: [] }, env: { allow: [] }, network: "none" };
      const context = { projectRoot: root, identity: { name: "probe", version: "1.0.0", packageDir, packageJsonPath: path.join(packageDir, "package.json") }, controlEnv: process.env, childEnv: { ...process.env, CAPLOCK_TEST_SECRET: "CAPLOCK_DO_NOT_LEAK_7391" }, timeoutMs: 20_000 };
      const probe = async (text: string): Promise<number> => (await this.run({ executable: cmd, args: ["/d", "/s", "/c", text] }, policy, context)).code;
      const packageWrite = await this.run({ executable: probeChild, args: ["--probe-write", path.join(packageDir, "package-write.txt")] }, policy, context);
      const projectRead = await probe(`type "${path.join(root, ".env")}"`);
      const projectWrite = await probe(`echo denied> "${path.join(root, "source.txt")}"`);
      const siblingWrite = await probe(`echo denied> "${path.join(sibling, "x.txt")}"`);
      const environment = await this.run({ executable: probeChild, args: ["--probe-env"] }, policy, context);
      checks.push(
        { name: "filesystem.package-write", ok: packageWrite.code === 0 && existsSync(path.join(packageDir, "package-write.txt")), detail: packageWrite.code === 0 ? "active native package ACL probe" : `native package probe failed: ${redactText(packageWrite.stderr.trim())}` },
        { name: "filesystem.project-secret-denied", ok: projectRead !== 0, detail: "active synthetic .env probe" },
        { name: "filesystem.project-write-denied", ok: projectWrite !== 0 && readFileSync(path.join(root, "source.txt"), "utf8") === "protected", detail: "active protected project write probe" },
        { name: "filesystem.sibling-write-denied", ok: siblingWrite !== 0 && !existsSync(path.join(sibling, "x.txt")), detail: "active sibling write probe" },
        { name: "environment.secret-hidden", ok: environment.code === 0 && !environment.stdout.includes("CAPLOCK_SECRET_SHOULD_NOT_LEAK_7391") && !environment.stderr.includes("CAPLOCK_SECRET_SHOULD_NOT_LEAK_7391"), detail: environment.code === 0 ? "native AppContainer child verified filtered secret and synthetic HOME/TEMP" : `native environment probe failed: ${redactText(environment.stderr.trim())}` },
        { name: "network.default-deny", ok: false, detail: "active Windows network contract probe has not passed" },
      );
    } catch (error) { checks.push({ name: "Windows filesystem/environment contract", ok: false, detail: error instanceof Error ? error.message : "probe failed" }); }
    finally { rmSync(root, { recursive: true, force: true }); }
    return checks;
  }
  async run(command: SandboxCommand, policy: Required<import("../types.js").Policy>, context: SandboxContext): Promise<SandboxResult> {
    const availability = await this.checkAvailability(); if (!availability.available) throw new Error(availability.detail);
    mkdirSync(path.join(os.tmpdir(), "caplock"), { recursive: true, mode: 0o700 });
    const sandboxRoot = mkdtempSync(path.join(os.tmpdir(), "caplock", "run-"));
    const childTemp = path.join(sandboxRoot, "child-temp"); const runtimeRoot = path.join(sandboxRoot, "runtime");
    mkdirSync(childTemp, { recursive: true, mode: 0o700 }); mkdirSync(runtimeRoot, { recursive: true, mode: 0o700 });
    const home = path.join(childTemp, "home"); mkdirSync(home, { recursive: true, mode: 0o700 });
    const controlEnv = context.controlEnv ?? process.env;
    const env = filterEnvironment(context.childEnv ?? controlEnv, policy.env?.allow ?? []);
    const parent = controlEnv;
    // This is the deliberately small, non-secret Windows runtime baseline for
    // the untrusted child. The helper itself receives controlEnv unchanged.
    for (const key of ["ALLUSERSPROFILE", "APPDATA", "ComSpec", "LOCALAPPDATA", "OS", "PATHEXT", "PROCESSOR_ARCHITECTURE", "ProgramData", "SystemDrive", "SystemRoot", "WINDIR"]) if (parent[key] && !/secret|token|password|key|credential|auth/i.test(key)) env[key] = parent[key]!;
    env.PATH = parent.Path ?? parent.PATH ?? env.PATH ?? "";
    Object.assign(env, { USERPROFILE: home, HOME: home, HOMEDRIVE: path.parse(home).root.slice(0, 2), HOMEPATH: home.slice(path.parse(home).root.length - 1), TEMP: home, TMP: home, SystemRoot: parent.SystemRoot ?? "C:\\Windows", WINDIR: parent.WINDIR ?? parent.SystemRoot ?? "C:\\Windows", ComSpec: parent.ComSpec ?? "C:\\Windows\\System32\\cmd.exe" });
    if (process.env.CAPLOCK_DEBUG === "1") {
      const required = ["SystemRoot", "WINDIR", "ComSpec", "PATH", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "HOME", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "APPDATA"];
      console.error(`CapLock child environment: entries=${Object.keys(env).length}; ${required.map((key) => `${key}=${env[key] ? "present" : "absent"}`).join("; ")}`);
    }
    const packageDir = realpathOrResolve(context.identity.packageDir);
    const cwd = realpathOrResolve(command.cwd ?? packageDir);
    if (!isWithin(cwd, packageDir)) throw new Error("Sandbox working directory must remain within the package.");
    const resolveGrant = (item: string): string => {
      const resolved = realpathOrResolve(substitutePolicyPath(item, context.projectRoot, packageDir, { home, tmp: childTemp }));
      const root = item.startsWith("$PACKAGE/") ? packageDir : item.startsWith("$PROJECT/") ? realpathOrResolve(context.projectRoot) : item.startsWith("$HOME/") ? home : childTemp;
      if (!isWithin(resolved, root)) throw new Error(`Policy grant resolves outside its allowed root: ${item}`);
      return resolved;
    };
    const reads = (policy.filesystem?.read ?? []).map(resolveGrant);
    const writes = (policy.filesystem?.write ?? []).map(resolveGrant);
    // The installed Node runtime is commonly under Program Files, whose DACL
    // cannot be modified by a normal developer account. Copy the exact trusted
    // executable into this owned run directory; it is a single self-contained
    // PE on supported Node 24 Windows builds.
    const stagedExecutables = (command.trustedExecutablePaths ?? []).map((source, index) => {
      const trustedSource = realpathOrResolve(source);
      const destination = path.join(runtimeRoot, `${index}-${path.basename(trustedSource)}`);
      copyFileSync(trustedSource, destination, 0);
      return { requested: source, source: trustedSource, destination: realpathOrResolve(destination), runtimeDirectory: runtimeRoot, index };
    });
    if (process.env.CAPLOCK_DEBUG === "1") for (const item of stagedExecutables) console.error(`CapLock staged executable: source=${item.source}; destination=${item.destination}`);
    for (const target of writes) mkdirSync(target, { recursive: true, mode: 0o700 });
    const envFile = path.join(childTemp, "child-environment.utf16");
    writeFileSync(envFile, serializeWindowsEnvironment(env), { mode: 0o600 });
    const stagedArgs = command.args.map((arg) => stagedExecutables.reduce((value, item) => value.replaceAll(item.requested, item.destination).replaceAll(item.source, item.destination), arg));
    const stagedCommandExecutable = stagedExecutables.find((item) => item.requested === command.executable || item.source === command.executable)?.destination ?? command.executable;
    const args = ["--package", packageDir, "--temp", childTemp, "--cwd", cwd, "--network", policy.network, "--env-file", envFile, ...reads.flatMap((item) => ["--read", item]), ...stagedExecutables.flatMap((item) => ["--read", item.runtimeDirectory, "--read", item.destination]), ...writes.flatMap((item) => ["--write", item]), "--", stagedCommandExecutable, ...stagedArgs];
    try { return await run(helperPath(), args, { env: controlEnv, timeoutMs: context.timeoutMs }); } finally { rmSync(sandboxRoot, { recursive: true, force: true }); }
  }
}
