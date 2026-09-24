import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import path from "node:path";
export const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");
export const normalizePath = (value: string): string => path.resolve(value).replaceAll("\\", "/");
export function isWithin(child: string, parent: string): boolean { const rel = path.relative(parent, child); return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel)); }
export function realpathOrResolve(value: string): string { try { return realpathSync.native(value); } catch { return path.resolve(value); } }

/** Keep diagnostics useful without emitting credentials embedded in commands or
 * child-process errors. This is deliberately applied at every CLI boundary. */
export function redactText(value: string): string {
  return value
    .replace(/\b([A-Za-z_][A-Za-z0-9_]*(?:token|secret|password|passwd|api[_-]?key|credential|auth)[A-Za-z0-9_]*)\s*=\s*([^\s'";]+)/gi, "$1=[REDACTED]")
    .replace(/(--(?:token|secret|password|passwd|api[_-]?key|credential|auth)[=\s]+)([^\s'";]+)/gi, "$1[REDACTED]");
}
