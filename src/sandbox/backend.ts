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
