import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import dns from "node:dns";
import { fileURLToPath } from "node:url";
import { filterEnvironment, substitutePolicyPath } from "../policy.js";
import { run } from "../process.js";
import { isWithin, realpathOrResolve } from "../util.js";
import { redactText } from "../util.js";
import type { DoctorCheck, Policy, SandboxAvailability, SandboxBackend, SandboxCapabilities, SandboxCommand, SandboxContext, SandboxResult } from "../types.js";

const capabilities: SandboxCapabilities = { filesystemIsolation: true, environmentIsolation: true, networkIsolation: true, processContainment: true, processObservation: false };
export function removeWindowsTempDirectory(directory: string): void {
  // Owned temporary trees only. Windows may briefly retain image/filesystem
  // references after process exit. Node retries transient EPERM/EBUSY/ENOTEMPTY
  // with bounded linear backoff, and still throws on permanent failure.
  rmSync(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
function helperPath(): string { return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../native/bin/caplock-sandbox.exe"); }
function pipeShimPath(): string { return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../native/bin/caplock-pipe-shim.node"); }
function pipePreloadPath(): string { return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../native/windows/caplock-pipe-preload.cjs"); }

function isNodeExecutable(value: string): boolean { return /^node(?:\.exe)?$/i.test(path.basename(value)); }
function trustedNodeOptions(preloadPath: string, shimPath: string): string {
  // NODE_OPTIONS has its own quoting grammar (independent of CreateProcess's
  // command-line quoting). Quote the preload path so a temp/runtime directory
  // containing spaces remains one --require argument.
  // Node's NODE_OPTIONS tokenizer treats backslashes as escapes even inside
  // quotes. Forward slashes preserve Windows drive paths without losing path
  // separators during option parsing.
  const nodeOptionPath = (value: string): string => {
    const nodePath = value.replaceAll("\\", "/");
    return /\s/.test(nodePath) ? `"${nodePath.replaceAll('"', '\\"')}"` : nodePath;
  };
  // Load the CJS bootstrap first. It requires the native addon normally and
  // records a path-free loader error before rethrowing.
  return `--preserve-symlinks --require=${nodeOptionPath(preloadPath)} --require=${nodeOptionPath(shimPath)}`;
}

/** CreateProcessW requires one NUL after every entry and one extra final NUL. */
export function serializeWindowsEnvironment(env: Record<string, string>): Buffer {
  const entries = Object.entries(env).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => {
    if (!key || key.includes("=") || value.includes("\0")) throw new Error("Invalid Windows child environment entry");
    return `${key}=${value}\0`;
  });
  return Buffer.from(entries.join("") + "\0", "utf16le");
}

/** One authoritative builder for lifecycle and doctor probe child environments. */
export function buildWindowsChildEnvironment(controlEnv: NodeJS.ProcessEnv, childInput: NodeJS.ProcessEnv, policy: Required<import("../types.js").Policy>, home: string): Record<string, string> {
  const env = filterEnvironment(childInput, policy.env?.allow ?? []);
  for (const key of ["ALLUSERSPROFILE", "APPDATA", "ComSpec", "LOCALAPPDATA", "OS", "PATHEXT", "PROCESSOR_ARCHITECTURE", "ProgramData", "SystemDrive", "SystemRoot", "WINDIR"]) if (controlEnv[key] && !/secret|token|password|key|credential|auth/i.test(key)) env[key] = controlEnv[key]!;
  env.PATH = controlEnv.Path ?? controlEnv.PATH ?? env.PATH ?? "";
  Object.assign(env, { USERPROFILE: home, HOME: home, HOMEDRIVE: path.parse(home).root.slice(0, 2), HOMEPATH: home.slice(path.parse(home).root.length - 1), TEMP: home, TMP: home, SystemRoot: controlEnv.SystemRoot ?? "C:\\Windows", WINDIR: controlEnv.WINDIR ?? controlEnv.SystemRoot ?? "C:\\Windows", ComSpec: controlEnv.ComSpec ?? "C:\\Windows\\System32\\cmd.exe" });
  return env;
}

function normalizeWindowsPath(value: string): string {
  const normalized = path.win32.normalize(path.win32.resolve(value.replaceAll("/", "\\"))).replace(/[\\]+$/, "");
  return normalized.toLocaleLowerCase("en-US");
}

export function windowsSyntheticEnvironmentMatches(actual: Record<string, string>, expected: Record<string, string>): boolean {
  const paths = ["HOME", "USERPROFILE", "TEMP", "TMP"];
  return paths.every((key) => actual[key] !== undefined && expected[key] !== undefined && normalizeWindowsPath(actual[key]!) === normalizeWindowsPath(expected[key]!))
    && (actual.HOMEDRIVE ?? "").toLocaleLowerCase("en-US") === (expected.HOMEDRIVE ?? "").toLocaleLowerCase("en-US")
    && (actual.HOMEPATH ?? "").replaceAll("/", "\\").replace(/[\\]+$/, "").toLocaleLowerCase("en-US") === (expected.HOMEPATH ?? "").replaceAll("/", "\\").replace(/[\\]+$/, "").toLocaleLowerCase("en-US");
}

/** Exercise AppContainer network capabilities with a real DNS request to the
 * configured resolver. This avoids localhost loopback exemptions and inbound
 * host-firewall rules while using the same production backend as lifecycles. */
export async function runWindowsNetworkContract(backend = new WindowsSandboxBackend()): Promise<{ defaultDeny: boolean; hostAllow: boolean; detail: string }> {
  const gateway = await defaultIPv4Gateway();
  const resolvers = [...new Set([...(gateway ? [gateway] : []), ...dns.getServers().filter(netIsRoutableIPv4)])];
  if (resolvers.length === 0) return { defaultDeny: false, hostAllow: false, detail: "No non-loopback IPv4 DNS resolver or default gateway is available for the active network contract." };
  const root = mkdtempSync(path.join(os.tmpdir(), "caplock-network-contract-"));
  try {
    const packageDir = path.join(root, "node_modules", "network-probe"); mkdirSync(packageDir, { recursive: true });
    const manifest = path.join(packageDir, "package.json"); writeFileSync(manifest, '{"name":"network-probe","version":"1.0.0"}');
    const identity = { name: "network-probe", version: "1.0.0", packageDir, packageJsonPath: manifest };
    const context = { projectRoot: root, identity, controlEnv: process.env, timeoutMs: 10_000 };
    const client = "const d=require('node:dgram');const s=d.createSocket('udp4');const id=0x4c43;const q=Buffer.from([0x4c,0x43,1,0,0,1,0,0,0,0,0,0,7,101,120,97,109,112,108,101,3,99,111,109,0,0,1,0,1]);const t=setTimeout(()=>{s.close();process.exit(15)},2500);s.on('message',m=>{clearTimeout(t);const ok=m.length>=12&&m.readUInt16BE(0)===id&&(m[2]&0x80)!==0;s.close();process.exit(ok?0:8)});s.on('error',e=>{clearTimeout(t);s.close();process.exit(e.code==='EACCES'?11:e.code==='EPERM'?12:e.code==='ENETUNREACH'?13:e.code==='EHOSTUNREACH'?14:16)});s.send(q,53,process.argv[1],e=>{if(e){clearTimeout(t);s.close();process.exit(e.code==='EACCES'?11:e.code==='EPERM'?12:16)}});";
    const nonePolicy: Required<Policy> = { filesystem: { read: [], write: [] }, env: { allow: [] }, network: "none" };
    const hostPolicy: Required<Policy> = { ...nonePolicy, network: "host" };
    let lastDetail = "No DNS endpoint returned a valid response under network:host.";
    for (const resolver of resolvers) {
      const command = { executable: process.execPath, args: ["-e", client, resolver], trustedExecutablePaths: [process.execPath] };
      const noneResult = await backend.run(command, nonePolicy, context);
      // AppContainer WFP filtering may silently drop UDP, yielding a bounded
      // timeout rather than WSAEACCES. The paired host-policy request must
      // succeed below for this to count as policy enforcement evidence.
      const hostResult = await backend.run(command, hostPolicy, context);
      const hostAllow = hostResult.code === 0;
      const defaultDeny = noneResult.code !== 0;
      lastDetail = `DNS endpoint ${resolver}: network:none ${defaultDeny ? `request failed (exit=${noneResult.code})` : "unexpectedly received a DNS response"}; identical network:host request ${hostAllow ? "received a valid DNS response" : `failed (exit=${hostResult.code})`}`;
      if (hostAllow) return { defaultDeny, hostAllow, detail: lastDetail };
    }
    return { defaultDeny: false, hostAllow: false, detail: lastDetail };
  } finally { removeWindowsTempDirectory(root); }
}

async function defaultIPv4Gateway(): Promise<string | undefined> {
  const routeExe = path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "route.exe");
  const result = await run(routeExe, ["print", "-4"], { timeoutMs: 3_000 });
  if (result.code !== 0) return undefined;
  const match = result.stdout.match(/^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+/m);
  return match && netIsRoutableIPv4(match[1]!) ? match[1] : undefined;
}

function netIsRoutableIPv4(value: string): boolean {
  const parts = value.split(".").map(Number);
  return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) && parts[0] !== 0 && parts[0] !== 127 && !(parts[0] === 169 && parts[1] === 254);
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
      const context = { projectRoot: root, identity: { name: "probe", version: "1.0.0", packageDir, packageJsonPath: path.join(packageDir, "package.json") }, controlEnv: process.env, childEnv: { ...process.env, CAPLOCK_TEST_SECRET: "CAPLOCK_SECRET_DO_NOT_LEAK_7391" }, timeoutMs: 20_000 };
      const probe = async (text: string): Promise<number> => (await this.run({ executable: cmd, args: ["/d", "/s", "/c", text] }, policy, context)).code;
      const packageWrite = await this.run({ executable: probeChild, args: ["--probe-write", path.join(packageDir, "package-write.txt")] }, policy, context);
      const projectRead = await probe(`type "${path.join(root, ".env")}"`);
      const projectWrite = await probe(`echo denied> "${path.join(root, "source.txt")}"`);
      const siblingWrite = await probe(`echo denied> "${path.join(sibling, "x.txt")}"`);
      const expectedRoot = mkdtempSync(path.join(os.tmpdir(), "caplock", "doctor-env-"));
      const expectedHome = path.join(expectedRoot, "child-temp", "home");
      const expectedEnvironment = buildWindowsChildEnvironment(context.controlEnv!, context.childEnv!, policy, expectedHome);
      const environment = await this.run({ executable: probeChild, args: ["--probe-env", expectedEnvironment.HOME!, expectedEnvironment.USERPROFILE!, expectedEnvironment.HOMEDRIVE!, expectedEnvironment.HOMEPATH!] }, policy, { ...context, sandboxRoot: expectedRoot });
      const actualEnvironment = Object.fromEntries(environment.stdout.split(/\r?\n/).filter((line) => line.includes("=")).map((line) => { const index = line.indexOf("="); return [line.slice(0, index), line.slice(index + 1)]; }));
      const appContainerTemp = actualEnvironment.APP_CONTAINER_TEMP;
      const expectedWithAppContainerTemp = appContainerTemp ? { ...expectedEnvironment, TEMP: appContainerTemp, TMP: appContainerTemp } : expectedEnvironment;
      const tempIsAppContainerOwned = typeof appContainerTemp === "string" && /\\packages\\caplock-[^\\]+\\ac\\temp\\?$/i.test(appContainerTemp.replaceAll("/", "\\"));
      if (process.env.CAPLOCK_DEBUG === "1") console.error(["CapLock Windows doctor environment probe:", `expected HOME=${expectedEnvironment.HOME}`, `actual HOME=${actualEnvironment.HOME ?? "<missing>"}`, `expected USERPROFILE=${expectedEnvironment.USERPROFILE}`, `actual USERPROFILE=${actualEnvironment.USERPROFILE ?? "<missing>"}`, `expected TEMP=${expectedWithAppContainerTemp.TEMP}`, `actual TEMP=${actualEnvironment.TEMP ?? "<missing>"}`, `expected TMP=${expectedWithAppContainerTemp.TMP}`, `actual TMP=${actualEnvironment.TMP ?? "<missing>"}`, `expected HOMEDRIVE=${expectedEnvironment.HOMEDRIVE}`, `actual HOMEDRIVE=${actualEnvironment.HOMEDRIVE ?? "<missing>"}`, `expected HOMEPATH=${expectedEnvironment.HOMEPATH}`, `actual HOMEPATH=${actualEnvironment.HOMEPATH ?? "<missing>"}`].join("\n"));
      checks.push(
        { name: "filesystem.package-write", ok: packageWrite.code === 0 && existsSync(path.join(packageDir, "package-write.txt")), detail: packageWrite.code === 0 ? "active native package ACL probe" : `native package probe failed: ${redactText(packageWrite.stderr.trim())}` },
        { name: "filesystem.project-secret-denied", ok: projectRead !== 0, detail: "active synthetic .env probe" },
        { name: "filesystem.project-write-denied", ok: projectWrite !== 0 && readFileSync(path.join(root, "source.txt"), "utf8") === "protected", detail: "active protected project write probe" },
        { name: "filesystem.sibling-write-denied", ok: siblingWrite !== 0 && !existsSync(path.join(sibling, "x.txt")), detail: "active sibling write probe" },
        { name: "environment.secret-hidden", ok: environment.code === 0 && tempIsAppContainerOwned && windowsSyntheticEnvironmentMatches(actualEnvironment, expectedWithAppContainerTemp) && !environment.stdout.includes("CAPLOCK_SECRET_DO_NOT_LEAK_7391") && !environment.stderr.includes("CAPLOCK_SECRET_DO_NOT_LEAK_7391"), detail: environment.code === 0 ? "native AppContainer child verified filtered secret, synthetic HOME/profile, and AppContainer-owned TEMP/TMP" : `native environment probe failed: ${redactText(environment.stderr.trim())}` },
      );
      const network = await runWindowsNetworkContract(this);
      checks.push(
        { name: "network.default-deny", ok: network.defaultDeny, detail: network.detail },
        { name: "network.host-allow", ok: network.hostAllow, detail: network.detail },
      );
    } catch (error) { checks.push({ name: "Windows filesystem/environment contract", ok: false, detail: error instanceof Error ? error.message : "probe failed" }); }
    finally { removeWindowsTempDirectory(root); }
    return checks;
  }
  async run(command: SandboxCommand, policy: Required<import("../types.js").Policy>, context: SandboxContext): Promise<SandboxResult> {
    const availability = await this.checkAvailability(); if (!availability.available) throw new Error(availability.detail);
    mkdirSync(path.join(os.tmpdir(), "caplock"), { recursive: true, mode: 0o700 });
    const sandboxRoot = context.sandboxRoot ?? mkdtempSync(path.join(os.tmpdir(), "caplock", "run-"));
    const childTemp = path.join(sandboxRoot, "child-temp"); const runtimeRoot = path.join(sandboxRoot, "runtime");
    mkdirSync(childTemp, { recursive: true, mode: 0o700 }); mkdirSync(runtimeRoot, { recursive: true, mode: 0o700 });
    const home = path.join(childTemp, "home"); mkdirSync(home, { recursive: true, mode: 0o700 });
    const controlEnv = context.controlEnv ?? process.env;
    const env = buildWindowsChildEnvironment(controlEnv, context.childEnv ?? controlEnv, policy, home);
    // NODE_OPTIONS is parsed before lifecycle code. It is neither CapLock
    // runtime state nor safe ambient input for a sandboxed Node descendant.
    delete env.NODE_OPTIONS;
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
    // libuv before 1.53 uses global named pipes for default child stdio.  The
    // trusted preload changes only libuv's private pipe namespace while the
    // process token is an AppContainer; it is inherited by nested Node
    // processes so their default pipes retain normal capture semantics.
    let pipeShimStaged = false;
    let stagedPipeShim: string | undefined;
    let stagedPipePreload: string | undefined;
    if (isNodeExecutable(command.executable)) {
      const sourceShim = pipeShimPath();
      const sourcePreload = pipePreloadPath();
      if (!existsSync(sourceShim)) throw new Error("Native Windows pipe compatibility shim is missing. Run npm run native:build.");
      if (!existsSync(sourcePreload)) throw new Error("Native Windows pipe compatibility preload is missing.");
      const shim = path.join(runtimeRoot, "caplock-pipe-shim.node");
      const preload = path.join(runtimeRoot, "caplock-pipe-preload.cjs");
      copyFileSync(sourceShim, shim, 0);
      copyFileSync(sourcePreload, preload, 0);
      if (!existsSync(shim) || !existsSync(preload)) throw new Error("Native Windows pipe compatibility preload was not staged.");
      stagedPipeShim = shim;
      stagedPipePreload = preload;
      pipeShimStaged = true;
      // This replaces, rather than merges with, any host or user NODE_OPTIONS.
      // The trusted preload then follows normal Node environment inheritance
      // for nested Node children.
      env.CAPLOCK_PIPE_SHIM_PATH = shim;
      // The native helper checked the exact suspended child token before it
      // resumed Node. This avoids relying solely on Node's addon-time token
      // query, which can report a restricted token on the lifecycle path.
      env.CAPLOCK_PIPE_SHIM_FORCE = "1";
      env.NODE_OPTIONS = trustedNodeOptions(preload, shim);
      // This is intentionally not secret-bearing and lets the fixture prove
      // that the native module registration and hook installation ran.
      if (controlEnv.CAPLOCK_DEBUG) env.CAPLOCK_PIPE_SHIM_DIAGNOSTIC = "1";
    }
    const pipeShimExists = stagedPipeShim !== undefined && existsSync(stagedPipeShim);
    if (process.env.CAPLOCK_DEBUG === "1") console.error(`CapLock Windows pipe shim: pipeShimStaged=${pipeShimStaged}; pipeShimExists=${pipeShimExists}; trustedNodeOptionsConfigured=${Boolean(env.NODE_OPTIONS)}; shim=${stagedPipeShim ? path.basename(stagedPipeShim) : "<not-applicable>"}; stagedPath=<redacted>`);
    if (process.env.CAPLOCK_DEBUG === "1") for (const item of stagedExecutables) console.error(`CapLock staged executable: source=${item.source}; destination=${item.destination}`);
    for (const target of writes) mkdirSync(target, { recursive: true, mode: 0o700 });
    const envFile = path.join(childTemp, "child-environment.utf16");
    writeFileSync(envFile, serializeWindowsEnvironment(env), { mode: 0o600 });
    const stagedArgs = command.args.map((arg) => stagedExecutables.reduce((value, item) => value.replaceAll(item.requested, item.destination).replaceAll(item.source, item.destination), arg));
    const stagedCommandExecutable = stagedExecutables.find((item) => item.requested === command.executable || item.source === command.executable)?.destination ?? command.executable;
    // The helper applies ACLs after staging. Directory inheritance does not
    // retroactively grant existing files, so the preload and native addon
    // require their own explicit read/execute grants just like node.exe.
    const trustedRuntimeAssets = [stagedPipeShim, stagedPipePreload].filter((item): item is string => item !== undefined);
    const args = ["--package", packageDir, "--temp", childTemp, "--cwd", cwd, "--network", policy.network, "--env-file", envFile, ...reads.flatMap((item) => ["--read", item]), ...stagedExecutables.flatMap((item) => ["--read", item.runtimeDirectory, "--read", item.destination]), ...trustedRuntimeAssets.flatMap((item) => ["--read", item]), ...writes.flatMap((item) => ["--write", item]), "--", stagedCommandExecutable, ...stagedArgs];
    try {
      const result = await run(helperPath(), args, { env: controlEnv, timeoutMs: context.timeoutMs });
      if (process.env.CAPLOCK_DEBUG === "1" && stagedPipeShim) {
        const loadedMarker = path.join(packageDir, "caplock-pipe-shim-entered.marker");
        console.error(`CapLock Windows pipe shim: pipeShimParentLoaded=${existsSync(loadedMarker)}; shim=${path.basename(stagedPipeShim)}; stagedPath=<redacted>`);
      }
      return result;
    // run() resolves on the helper's close event, after process exit and stdio
    // closure. The helper drains its Job before returning (including children).
    } finally { removeWindowsTempDirectory(sandboxRoot); }
  }
}
