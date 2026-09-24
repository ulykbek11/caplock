import { existsSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import YAML from "yaml";
import type { Lifecycle, PackageIdentity } from "./types.js";
import { sha256 } from "./util.js";
function npmLockIntegrity(packageDir: string, projectRoot: string): string | undefined {
  const lockPath = path.join(projectRoot, "package-lock.json");
  if (!existsSync(lockPath)) return undefined;
  try {
    const lock = JSON.parse(readFileSync(lockPath, "utf8")) as { packages?: Record<string, { integrity?: unknown }> };
    const key = path.relative(projectRoot, packageDir).replaceAll("\\", "/");
    const integrity = lock.packages?.[key]?.integrity;
    return typeof integrity === "string" ? integrity : undefined;
  } catch { return undefined; }
}

/** pnpm's package snapshots contain the immutable content integrity. */
function pnpmLockIntegrity(projectRoot: string, name: string, version: string): string | undefined {
  const lockPath = path.join(projectRoot, "pnpm-lock.yaml");
  if (!existsSync(lockPath)) return undefined;
  try {
    const lock = YAML.parse(readFileSync(lockPath, "utf8")) as { packages?: Record<string, { resolution?: { integrity?: unknown } }> };
    const snapshot = Object.entries(lock.packages ?? {}).find(([key]) => key === `${name}@${version}` || key === `/${name}@${version}` || key.startsWith(`${name}@${version}(`))?.[1];
    return typeof snapshot?.resolution?.integrity === "string" ? snapshot.resolution.integrity : undefined;
  } catch { return undefined; }
}

export function identifyPackage(cwd: string, projectRoot: string): PackageIdentity {
  let current = path.resolve(cwd); const stop = path.parse(current).root;
  while (true) { const json = path.join(current, "package.json"); if (existsSync(json)) { const raw = JSON.parse(readFileSync(json, "utf8")) as { name?: unknown; version?: unknown }; if (typeof raw.name !== "string" || typeof raw.version !== "string") throw new Error(`Package metadata missing name/version: ${json}`); return { name: raw.name, version: raw.version, packageDir: current, packageJsonPath: json, integrity: npmLockIntegrity(current, projectRoot) ?? pnpmLockIntegrity(projectRoot, raw.name, raw.version) }; } if (current === stop || current === projectRoot) break; current = path.dirname(current); }
  throw new Error(`No package.json found above ${cwd}`);
}

function canonicalPath(value: string): string {
  return realpathSync.native(value);
}

function isWithin(child: string, parent: string): boolean {
  const relative = path.relative(parent, child);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

/**
 * A lifecycle is eligible for dependency sandboxing only when its resolved
 * package root remains inside this project's resolved node_modules tree.
 * This deliberately rejects file: and workspace links that resolve elsewhere.
 */
export function isExternalInstalledPackage(identity: PackageIdentity, projectRoot: string): boolean {
  try {
    const nodeModules = canonicalPath(path.join(projectRoot, "node_modules"));
    const packageDir = canonicalPath(identity.packageDir);
    const manifest = canonicalPath(identity.packageJsonPath);
    return isWithin(packageDir, nodeModules) && manifest === path.join(packageDir, "package.json");
  } catch { return false; }
}

/** Compare resolved package roots so junctions cannot spoof package metadata. */
export function samePackageRoot(a: PackageIdentity, b: PackageIdentity): boolean {
  try { return canonicalPath(a.packageDir) === canonicalPath(b.packageDir); } catch { return false; }
}
export function lifecycleFromEnv(env: NodeJS.ProcessEnv): Lifecycle | undefined { const event = env.npm_lifecycle_event; const command = env.npm_lifecycle_script; if ((event !== "preinstall" && event !== "install" && event !== "postinstall") || !command) return undefined; return { event, command, hash: sha256(command) }; }

/** npm 11 can retain the parent npm_lifecycle_event when invoking a custom
 * script-shell. Bind the invocation to the installed package manifest instead
 * of trusting that inherited value. Ambiguous commands deliberately fail. */
export function lifecycleFromPackage(packageDir: string, command: string): Lifecycle | undefined {
  try {
    const pkg = JSON.parse(readFileSync(path.join(packageDir, "package.json"), "utf8")) as { scripts?: Record<string, unknown> };
    const matches = (["preinstall", "install", "postinstall"] as const).filter((event) => pkg.scripts?.[event] === command);
    if (matches.length !== 1) return undefined;
    return { event: matches[0]!, command, hash: sha256(command) };
  } catch { return undefined; }
}
