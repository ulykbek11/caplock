import { afterEach, describe, expect, it, vi } from "vitest";
import { rmSync } from "node:fs";
import { removeWindowsTempDirectory } from "../src/sandbox/windows.js";

vi.mock("node:fs", async (original) => ({ ...await original<typeof import("node:fs")>(), rmSync: vi.fn() }));
afterEach(() => vi.mocked(rmSync).mockReset());

describe("Windows owned temporary directory cleanup", () => {
  it("uses bounded transient-error retries", () => {
    removeWindowsTempDirectory("owned-temp-fixture");
    expect(rmSync).toHaveBeenCalledWith("owned-temp-fixture", { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });
  it.each(["EPERM", "EBUSY", "ENOTEMPTY"])("propagates permanent %s after retries are exhausted", (code) => {
    const error = Object.assign(new Error("cleanup failed"), { code });
    vi.mocked(rmSync).mockImplementation(() => { throw error; });
    expect(() => removeWindowsTempDirectory("owned-temp-fixture")).toThrow(error);
  });
});
