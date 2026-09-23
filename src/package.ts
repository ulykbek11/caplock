import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import type { Lifecycle, PackageIdentity } from "./types.js";
import { sha256 } from "./util.js";
function lockIntegrity(packageDir: string, projectRoot: string): string | undefined {
  const lockPath = path.join(projectRoot, "package-lock.json");
  if (!existsSync(lockPath)) return undefined;
  try {
    const lock = JSON.parse(readFileSync(lockPath, "utf8")) as { packages?: Record<string, { integrity?: unknown }> };
    const key = path.relative(projectRoot, packageDir).replaceAll("\\", "/");
    const integrity = lock.packages?.[key]?.integrity;
    return typeof integrity === "string" ? integrity : undefined;
  } catch { return undefined; }
}

export function identifyPackage(cwd: string, projectRoot: string): PackageIdentity {
  let current = path.resolve(cwd); const stop = path.parse(current).root;
  while (true) { const json = path.join(current, "package.json"); if (existsSync(json)) { const raw = JSON.parse(readFileSync(json, "utf8")) as { name?: unknown; version?: unknown }; if (typeof raw.name !== "string" || typeof raw.version !== "string") throw new Error(`Package metadata missing name/version: ${json}`); return { name: raw.name, version: raw.version, packageDir: current, packageJsonPath: json, integrity: lockIntegrity(current, projectRoot) }; } if (current === stop || current === projectRoot) break; current = path.dirname(current); }
  throw new Error(`No package.json found above ${cwd}`);
}
export function lifecycleFromEnv(env: NodeJS.ProcessEnv): Lifecycle | undefined { const event = env.npm_lifecycle_event; const command = env.npm_lifecycle_script; if ((event !== "preinstall" && event !== "install" && event !== "postinstall") || !command) return undefined; return { event, command, hash: sha256(command) }; }
