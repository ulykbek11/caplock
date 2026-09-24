import { describe, expect, it } from "vitest";
import { serializeWindowsEnvironment } from "../src/sandbox/windows.js";

describe("Windows CreateProcess environment serialization", () => {
  it("ends with two UTF-16 NUL WCHARs", () => {
    const block = serializeWindowsEnvironment({ SystemRoot: "C:\\Windows", TEMP: "C:\\temp" });
    expect(block.length % 2).toBe(0);
    expect(block.readUInt16LE(block.length - 2)).toBe(0);
    expect(block.readUInt16LE(block.length - 4)).toBe(0);
  });
});
