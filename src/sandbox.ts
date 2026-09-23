import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { filterEnvironment, substitutePolicyPath } from "./policy.js";
import { run } from "./process.js";
import type { PackageIdentity, Policy } from "./types.js";

const systemPaths = ["/usr", "/bin", "/lib", "/lib64", "/sbin", "/etc"];
export function bwrapArgs(command: string, identity: PackageIdentity, projectRoot: string, policy: Required<Policy>, traceFile?: string): string[] {
  const args = ["--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-user", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/home", "--dir", "/home/caplock"];
  if (policy.network === "none") args.push("--unshare-net");
  for (const p of systemPaths) if (existsSync(p)) args.push("--ro-bind", p, p);
  const projectPackage = path.join(projectRoot, "package.json"); if (existsSync(projectPackage)) args.push("--ro-bind", projectPackage, projectPackage);
  const projectLock = path.join(projectRoot, "package-lock.json"); if (existsSync(projectLock)) args.push("--ro-bind", projectLock, projectLock);
  const modules = path.join(projectRoot, "node_modules"); if (existsSync(modules)) args.push("--ro-bind", modules, modules);
  // Rebinding the executing package after node_modules makes only that package writable.
  args.push("--bind", identity.packageDir, identity.packageDir);
  for (const p of policy.filesystem?.read ?? []) { const target = substitutePolicyPath(p, projectRoot, identity.packageDir, { home: "/home/caplock", tmp: "/tmp" }); if (existsSync(target)) args.push("--ro-bind", target, target); }
  for (const p of policy.filesystem?.write ?? []) { const target = substitutePolicyPath(p, projectRoot, identity.packageDir, { home: "/home/caplock", tmp: "/tmp" }); mkdirSync(target, { recursive: true }); args.push("--bind", target, target); }
  const env = filterEnvironment(process.env, policy.env?.allow ?? []); for (const [key, value] of Object.entries(env)) args.push("--setenv", key, value);
  args.push("--chdir", identity.packageDir, "--");
  if (traceFile) args.push("strace", "-f", "-qq", "-o", traceFile, "-e", "trace=file,network,process");
  return [...args, "/bin/sh", "-c", command];
}
export async function runSandbox(command: string, identity: PackageIdentity, projectRoot: string, policy: Required<Policy>, traceFile?: string, timeoutMs = 300_000): Promise<number> { const result = await run("bwrap", bwrapArgs(command, identity, projectRoot, policy, traceFile), { inherit: true, timeoutMs }); return result.code; }
