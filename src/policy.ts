import path from "node:path";
import { z } from "zod";
import type { NetworkMode, Policy } from "./types.js";
import { existsSync, lstatSync, realpathSync } from "node:fs";
import { isWithin, normalizePath } from "./util.js";

export const SECRET_ENV = /(?:token|secret|password|passwd|api[_-]?key|credential|private[_-]?key|auth)/i;
const forbidden = [".env", ".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmrc", ".netrc", ".git-credentials", ".git", ".ssh", ".aws", ".gnupg", ".kube"];
const schema = z.object({ filesystem: z.object({ read: z.array(z.string()).optional(), write: z.array(z.string()).optional() }).optional(), env: z.object({ allow: z.array(z.string()).optional() }).optional(), network: z.enum(["none", "host"]).optional() }).strict();
export const defaultPolicy = (): Required<Policy> => ({ filesystem: { read: [], write: [] }, env: { allow: ["PATH", "HOME", "TMPDIR", "npm_*", "NODE_*", "npm_config_*"].filter((x) => !x.includes("*")) }, network: "none" });
export function validatePolicy(input: unknown, projectRoot: string, packageDir: string): Required<Policy> {
  const p = schema.parse(input); const out = defaultPolicy(); const filesystem = out.filesystem!;
  for (const [kind, values] of [["read", p.filesystem?.read ?? []], ["write", p.filesystem?.write ?? []]] as const) {
    filesystem[kind] = values.map((v) => validatePolicyPath(v, projectRoot, packageDir));
  }
  const names = p.env?.allow ?? out.env!.allow ?? [];
  for (const name of names) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(`Invalid environment variable name in policy: ${name}`);
    if (SECRET_ENV.test(name)) throw new Error(`Sensitive environment variable cannot be allowed: ${name}`);
  }
  out.env!.allow = names;
  out.network = (p.network ?? "none") as NetworkMode; return out;
}
export function validatePolicyPath(value: string, projectRoot: string, packageDir: string): string {
  if (value.startsWith("$HOME/") || value.startsWith("$TMP/")) return value;
  if (!value.startsWith("$PROJECT/") && !value.startsWith("$PACKAGE/")) throw new Error(`Policy path must start with $PROJECT, $PACKAGE, $HOME, or $TMP: ${value}`);
  const root = value.startsWith("$PROJECT/") ? projectRoot : packageDir;
  const suffix = value.replace(/^\$(PROJECT|PACKAGE)\//, ""); const resolved = normalizePath(path.join(root, suffix));
  if (!isWithin(resolved, normalizePath(root))) throw new Error(`Policy path escapes its root: ${value}`);
  if (value.startsWith("$PROJECT/") && isSensitiveProjectPath(suffix)) throw new Error(`Sensitive project path cannot be exposed: ${value}`);
  // A bind mount follows source symlinks.  Reject explicit grants that traverse one,
  // rather than relying on a lexical path check that could point outside its root.
  let probe = normalizePath(root); for (const part of suffix.split("/")) { probe = path.join(probe, part); if (existsSync(probe) && lstatSync(probe).isSymbolicLink()) { const target = realpathSync.native(probe); if (!isWithin(target, normalizePath(root))) throw new Error(`Policy path traverses a symlink outside its root: ${value}`); } }
  return value;
}
export function substitutePolicyPath(value: string, projectRoot: string, packageDir: string, dynamic: { home?: string; tmp?: string } = {}): string {
  return value.replace("$PROJECT", projectRoot).replace("$PACKAGE", packageDir).replace("$HOME", dynamic.home ?? "$HOME").replace("$TMP", dynamic.tmp ?? "$TMP");
}
export function isSensitiveProjectPath(relative: string): boolean { return relative.split("/").some((part) => forbidden.includes(part) || part.startsWith(".env.")); }
export function filterEnvironment(env: NodeJS.ProcessEnv, allowed: string[]): Record<string, string> {
  const result: Record<string, string> = { HOME: "/home/caplock", PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", TMPDIR: "/tmp", TMP: "/tmp" };
  // These locations are CapLock-controlled regardless of a policy allowlist.
  // Carrying a host HOME/TEMP back into the child would defeat isolation.
  const synthetic = new Set(["HOME", "PATH", "TMP", "TMPDIR", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"]);
  for (const [key, value] of Object.entries(env)) if (value && !synthetic.has(key.toUpperCase()) && !SECRET_ENV.test(key) && (allowed.includes(key) || key.startsWith("npm_") || key.startsWith("NODE_"))) result[key] = value;
  return result;
}
