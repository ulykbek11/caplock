import { existsSync, readFileSync, renameSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { z } from "zod";
import { LOCKFILE_NAME, STATE_DIR_NAME } from "./constants.js";
import type { LockEntry, Lockfile } from "./types.js";
const policySchema = z.object({ filesystem: z.object({ read: z.array(z.string()), write: z.array(z.string()) }).strict(), env: z.object({ allow: z.array(z.string()) }).strict(), network: z.enum(["none", "host"]) }).strict();
const lockSchema = z.object({ version: z.literal(1), packages: z.array(z.object({ package: z.object({ name: z.string().min(1), version: z.string().min(1), integrity: z.string().min(1).optional() }).strict(), lifecycle: z.object({ event: z.enum(["preinstall", "install", "postinstall"]), command: z.string().min(1), hash: z.string().regex(/^[a-f0-9]{64}$/) }).strict(), policy: policySchema }).strict()) }).strict();
export function lockfilePath(root: string): string { return path.join(root, STATE_DIR_NAME, LOCKFILE_NAME); }
export function readLockfile(root: string): Lockfile {
  const file = lockfilePath(root); if (!existsSync(file)) return { version: 1, packages: [] };
  const parsed: unknown = YAML.parse(readFileSync(file, "utf8"));
  try { return lockSchema.parse(parsed) as Lockfile; } catch { throw new Error("Invalid caplock.lock schema"); }
}
export function writeLockfile(root: string, lock: Lockfile): void {
  const file = lockfilePath(root); mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  lock.packages.sort((a, b) => `${a.package.name}@${a.package.version}:${a.lifecycle.event}`.localeCompare(`${b.package.name}@${b.package.version}:${b.lifecycle.event}`));
  const temporary = `${file}.${process.pid}.${Date.now()}.tmp`; writeFileSync(temporary, YAML.stringify(lock), { encoding: "utf8", mode: 0o600 }); renameSync(temporary, file);
}
export function lockKey(entry: Pick<LockEntry, "package" | "lifecycle">): string { return `${entry.package.name}@${entry.package.version}:${entry.package.integrity ?? ""}:${entry.lifecycle.event}`; }
export function findLock(lock: Lockfile, candidate: Pick<LockEntry, "package" | "lifecycle">): LockEntry | undefined { return lock.packages.find((x) => lockKey(x) === lockKey(candidate)); }
