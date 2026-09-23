import { describe, expect, it } from "vitest";
import { selectSandboxBackend } from "../src/sandbox/backend.js";

describe("native backend selection", () => {
  it("selects Windows without requiring WSL", () => expect(selectSandboxBackend("win32").id).toBe("windows-native"));
  it("selects Bubblewrap on Linux", () => expect(selectSandboxBackend("linux").id).toBe("linux-bubblewrap"));
  it("selects native Seatbelt on macOS", () => expect(selectSandboxBackend("darwin").id).toBe("macos-native"));
  it("rejects unknown platforms instead of running scripts unsandboxed", () => expect(() => selectSandboxBackend("freebsd" as NodeJS.Platform)).toThrow(/does not support/));
});
