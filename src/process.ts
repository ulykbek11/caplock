import { spawn, type ChildProcess } from "node:child_process";
export interface RunResult { code: number; stdout: string; stderr: string }
const lifecycleControlKeys = new Set(["npm_lifecycle_event", "npm_lifecycle_script", "npm_package_json", "npm_package_name", "npm_package_version", "npm_command"]);
/** Remove only inherited npm lifecycle identity. The next package-manager
 * process creates authoritative metadata for its own script invocation. */
export function cleanPackageManagerControlEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const clean: NodeJS.ProcessEnv = { ...env };
  for (const key of lifecycleControlKeys) delete clean[key];
  return clean;
}
export function run(command: string, args: string[], options: { cwd?: string; env?: NodeJS.ProcessEnv; inherit?: boolean; timeoutMs?: number; passFds?: number[] } = {}): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const isBatch = process.platform === "win32" && /\.cmd$/i.test(command);
    const quoteForCmd = (value: string) => /[\s&|<>()^%! "]/u.test(value) ? `"${value.replaceAll("^", "^^").replaceAll("%", "%%").replaceAll("!", "^^!").replaceAll('"', '\\"')}"` : value;
    const commandLine = [command, ...args.map(quoteForCmd)].join(" ");
    const stdio: (number | "ignore" | "pipe")[] = options.passFds ? ["ignore", "pipe", "pipe", ...options.passFds] : ["pipe", "pipe", "pipe"];
    let child: ChildProcess;
    if (isBatch) child = spawn(process.env.ComSpec ?? "C:\\Windows\\System32\\cmd.exe", ["/d", "/s", "/c", commandLine], { cwd: options.cwd, env: options.env, stdio: options.inherit ? "inherit" : "pipe", shell: false });
    else child = spawn(command, args, { cwd: options.cwd, env: options.env, stdio: options.passFds ? stdio : options.inherit ? "inherit" : "pipe", detached: process.platform !== "win32", shell: false });
    let stdout = "", stderr = "", timedOut = false;
    const timer = options.timeoutMs ? setTimeout(() => { timedOut = true; if (process.platform !== "win32" && child.pid) process.kill(-child.pid, "SIGKILL"); else child.kill("SIGKILL"); }, options.timeoutMs) : undefined;
    if (!options.inherit) { child.stdout?.on("data", (x: Buffer) => { stdout += x; }); child.stderr?.on("data", (x: Buffer) => { stderr += x; }); }
    child.on("error", reject);
    child.on("close", (code) => { if (timer) clearTimeout(timer); resolve({ code: timedOut ? 124 : code ?? 1, stdout, stderr }); });
  });
}
export async function commandExists(command: string): Promise<boolean> {
  try {
    // `where` can miss user-level Corepack shims in constrained Windows
    // sessions. Probe the exact .cmd launcher that lifecycle E2E will use.
    if (process.platform === "win32" && (command === "npm" || command === "pnpm")) return (await run(packageManagerCommand(command), ["--version"], { timeoutMs: 30_000 })).code === 0;
    return (await run(process.platform === "win32" ? "where.exe" : "which", [command])).code === 0;
  } catch { return false; }
}
export const packageManagerCommand = (name: string): string => process.platform === "win32" ? `${name}.cmd` : name;
