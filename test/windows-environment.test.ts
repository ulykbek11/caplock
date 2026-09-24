import { describe, expect, it } from "vitest";
import { buildWindowsChildEnvironment, serializeWindowsEnvironment, windowsSyntheticEnvironmentMatches } from "../src/sandbox/windows.js";
import { defaultPolicy } from "../src/policy.js";

describe("Windows CreateProcess environment serialization", () => {
  it("ends with two UTF-16 NUL WCHARs", () => {
    const block = serializeWindowsEnvironment({ SystemRoot: "C:\\Windows", TEMP: "C:\\temp" });
    expect(block.length % 2).toBe(0);
    expect(block.readUInt16LE(block.length - 2)).toBe(0);
    expect(block.readUInt16LE(block.length - 4)).toBe(0);
  });

  it("uses the same synthetic paths for HOME, profile and temp and tolerates Windows separator/case differences", () => {
    const expected = buildWindowsChildEnvironment({ SystemRoot: "C:\\Windows", Path: "C:\\Windows\\System32" }, { CAPLOCK_TEST_SECRET: "do-not-copy" }, defaultPolicy(), "C:\\Users\\Example\\AppData\\Local\\Temp\\caplock\\run-1\\child-temp\\home");
    expect(expected).not.toHaveProperty("CAPLOCK_TEST_SECRET");
    expect(expected.USERPROFILE).toBe(expected.HOME);
    expect(expected.TEMP).toBe(expected.HOME);
    expect(expected.TMP).toBe(expected.HOME);
    expect(windowsSyntheticEnvironmentMatches({
      HOME: "c:/users/example/appdata/local/temp/caplock/run-1/child-temp/home/",
      USERPROFILE: "C:/Users/Example/AppData/Local/Temp/caplock/run-1/child-temp/home",
      TEMP: "c:/USERS/example/AppData/Local/Temp/caplock/run-1/child-temp/home",
      TMP: "C:\\Users\\Example\\AppData\\Local\\Temp\\caplock\\run-1\\child-temp\\home\\",
      HOMEDRIVE: "c:", HOMEPATH: "\\Users\\Example\\AppData\\Local\\Temp\\caplock\\run-1\\child-temp\\home\\",
    }, expected)).toBe(true);
  });

  it("accepts Windows AppContainer TEMP/TMP virtualization only at the reported container temp path", () => {
    const home = "C:\\Users\\Example\\AppData\\Local\\Temp\\caplock\\run-2\\child-temp\\home";
    const expected = buildWindowsChildEnvironment({ SystemRoot: "C:\\Windows" }, {}, defaultPolicy(), home);
    const actual = { ...expected, TEMP: "C:\\Users\\Example\\AppData\\Local\\Packages\\CapLock-123-456\\AC\\Temp", TMP: "C:/Users/Example/AppData/Local/Packages/caplock-123-456/AC/Temp/" };
    expect(windowsSyntheticEnvironmentMatches(actual, { ...expected, TEMP: actual.TEMP, TMP: actual.TEMP })).toBe(true);
    expect(windowsSyntheticEnvironmentMatches({ ...actual, TMP: "C:\\Users\\Example\\Downloads" }, { ...expected, TEMP: actual.TEMP, TMP: actual.TEMP })).toBe(false);
  });
});
