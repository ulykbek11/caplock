import { accessSync, constants, mkdirSync } from "node:fs";
import path from "node:path";
import { STATE_DIR_NAME } from "./constants.js";
import { run } from "./process.js";
import { selectSandboxBackend } from "./sandbox/backend.js";
import type { DoctorCheck as Check } from "./types.js";
export type { Check };
export async function doctor(root: string): Promise<Check[]> {
  const checks: Check[] = [{ name: "Platform", ok: ["win32", "linux", "darwin"].includes(process.platform), detail: process.platform }, { name: "Node >= 24", ok: Number(process.versions.node.split(".")[0]) >= 24, detail: process.version }];
  try { const npm = process.platform === "win32" ? await run("cmd.exe", ["/d", "/s", "/c", "npm.cmd --version"]) : await run("npm", ["--version"]); checks.push({ name: "npm", ok: npm.code === 0, detail: npm.code === 0 ? npm.stdout.trim() : "npm not found" }); } catch { checks.push({ name: "npm", ok: false, detail: "npm not found" }); }
  try { checks.push(...await selectSandboxBackend().doctor()); } catch (error) { checks.push({ name: "native sandbox backend", ok: false, detail: error instanceof Error ? error.message : String(error) }); }
  const state = path.join(root, STATE_DIR_NAME); try { mkdirSync(state, { recursive: true }); accessSync(state, constants.W_OK); checks.push({ name: ".caplock writable", ok: true, detail: state }); } catch { checks.push({ name: ".caplock writable", ok: false, detail: state }); }
  return checks;
}
