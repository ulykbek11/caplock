import type { SandboxBackend } from "../types.js";
import { LinuxBubblewrapBackend } from "./linux.js";
import { MacOSSandboxBackend } from "./macos.js";
import { WindowsSandboxBackend } from "./windows.js";

/** Selects the native backend. There is deliberately no unrestricted fallback. */
export function selectSandboxBackend(platform: NodeJS.Platform = process.platform): SandboxBackend {
  switch (platform) {
    case "win32": return new WindowsSandboxBackend();
    case "linux": return new LinuxBubblewrapBackend();
    case "darwin": return new MacOSSandboxBackend();
    default: throw new Error(`CapLock does not support ${platform}; lifecycle scripts will not be run.`);
  }
}

/** Cheap fail-closed gate for every lifecycle. Full doctor probes remain an
 * explicit release verification step, rather than an expensive install step. */
export async function preflightSandbox(policy: Required<import("../types.js").Policy>): Promise<void> {
  const backend = selectSandboxBackend();
  const availability = await backend.checkAvailability();
  if (!availability.available) throw new Error(`CapLock sandbox preflight failed: ${availability.detail}`);
  const c = availability.capabilities;
  if (!c.filesystemIsolation || !c.environmentIsolation || !c.processContainment || (policy.network === "none" && !c.networkIsolation)) {
    throw new Error("CapLock sandbox preflight failed: required security properties are unavailable.");
  }
}
