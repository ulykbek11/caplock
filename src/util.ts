import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import path from "node:path";
export const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");
export const normalizePath = (value: string): string => path.resolve(value).replaceAll("\\", "/");
export function isWithin(child: string, parent: string): boolean { const rel = path.relative(parent, child); return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel)); }
export function realpathOrResolve(value: string): string { try { return realpathSync.native(value); } catch { return path.resolve(value); } }
