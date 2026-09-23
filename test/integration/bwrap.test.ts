import { describe, expect, it } from "vitest";
import { commandExists, run } from "../../src/process.js";

const runnable = process.platform === "linux" && await commandExists("bwrap");
describe.skipIf(!runnable)("Bubblewrap integration", () => {
  it("creates a private HOME and network namespace", async () => {
    const result = await run("bwrap", ["--unshare-user", "--unshare-net", "--ro-bind", "/usr", "/usr", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/home", "--dir", "/home/caplock", "--setenv", "HOME", "/home/caplock", "/bin/sh", "-c", "test \"$HOME\" = /home/caplock && test ! -e /home/caplock/.ssh"]);
    expect(result.code).toBe(0);
  });
});
