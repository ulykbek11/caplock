import { describe, expect, it } from "vitest";
import { buildLinuxInvocation } from "../src/sandbox/linux.js";
import { defaultPolicy } from "../src/policy.js";
describe("production Bubblewrap arguments", () => {
  it("uses a parent-owned isolated network namespace for network:none without configuring loopback", () => {
    const identity = { name: "pkg", version: "1", packageDir: "/project/node_modules/pkg", packageJsonPath: "x" };
    const context = { projectRoot: "/project", identity };
    const invocation = buildLinuxInvocation({ executable: "/bin/sh", args: ["-c", "echo ok"] }, defaultPolicy(), context);
    expect(invocation.executable).toBe("unshare");
    expect(invocation.args.slice(0, 5)).toEqual(["--user", "--map-root-user", "--net", "--", "bwrap"]);
    expect(invocation.args).toContain("--share-net");
    expect(invocation.args).not.toContain("--unshare-net");
    expect(invocation.args).toContain("/home/caplock");
    expect(invocation.args).toContain("--bind");
  });

  it("keeps network:host in the host network namespace", () => {
    const identity = { name: "pkg", version: "1", packageDir: "/project/node_modules/pkg", packageJsonPath: "x" };
    const policy = { ...defaultPolicy(), network: "host" as const };
    const invocation = buildLinuxInvocation({ executable: "/bin/sh", args: ["-c", "echo ok"] }, policy, { projectRoot: "/project", identity });
    expect(invocation.executable).toBe("bwrap");
    expect(invocation.args).toContain("--unshare-user");
    expect(invocation.args).toContain("--share-net");
    expect(invocation.args).not.toContain("--unshare-net");
  });
});
