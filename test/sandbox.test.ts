import { describe, expect, it } from "vitest";
import { buildLinuxInvocation, networkDenyFilter } from "../src/sandbox/linux.js";
import { defaultPolicy } from "../src/policy.js";
describe("production Bubblewrap arguments", () => {
  it("seals an empty project mount after overlaying the writable package", () => {
    const projectRoot = "/tmp/project";
    const packageDir = "/tmp/project/node_modules/pkg";
    const { args } = buildLinuxInvocation({ executable: "/bin/sh", args: [] }, defaultPolicy(), { projectRoot, identity: { name: "pkg", version: "1", packageDir, packageJsonPath: "x" } });
    const projectMount = args.findIndex((arg, i) => arg === "--tmpfs" && args[i + 1] === projectRoot);
    const packageMount = args.findIndex((arg, i) => arg === "--bind" && args[i + 1] === packageDir);
    const seal = args.indexOf("--remount-ro");
    expect(projectMount).toBeGreaterThan(0);
    expect(packageMount).toBeGreaterThan(projectMount);
    expect(seal).toBeGreaterThan(packageMount);
    expect(args[seal + 1]).toBe(projectRoot);
    expect(args.some((arg, i) => ["--bind", "--ro-bind"].includes(arg) && args[i + 1] === projectRoot)).toBe(false);
  });
  it.each(["none", "host"] as const)("clears inherited environment before setting filtered values for network:%s", (network) => {
    const identity = { name: "pkg", version: "1", packageDir: "/project/node_modules/pkg", packageJsonPath: "x" };
    const policy = { ...defaultPolicy(), network };
    const { args } = buildLinuxInvocation({ executable: "/bin/sh", args: [] }, policy, {
      projectRoot: "/project", identity,
      childEnv: { CAPLOCK_TEST_SECRET: "must-not-survive", ARBITRARY_HOST_VALUE: "unlisted", HOME: "/host", TMP: "/host/tmp", npm_lifecycle_event: "postinstall", NODE_NO_WARNINGS: "1" },
    });
    expect(args.filter((arg) => arg === "--clearenv")).toHaveLength(1);
    expect(args.indexOf("--clearenv")).toBeLessThan(args.indexOf("--setenv"));
    const env = Object.fromEntries(args.flatMap((arg, i) => arg === "--setenv" ? [[args[i + 1], args[i + 2]]] : []));
    expect(env).toEqual({ HOME: "/home/caplock", TMP: "/tmp", TMPDIR: "/tmp", PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", npm_lifecycle_event: "postinstall", NODE_NO_WARNINGS: "1" });
  });
  it("passes an OS-enforced network-deny filter for network:none without configuring loopback", () => {
    const identity = { name: "pkg", version: "1", packageDir: "/project/node_modules/pkg", packageJsonPath: "x" };
    const context = { projectRoot: "/project", identity };
    const invocation = buildLinuxInvocation({ executable: "/bin/sh", args: ["-c", "echo ok"] }, defaultPolicy(), context);
    expect(invocation.executable).toBe("bwrap");
    expect(invocation.args.slice(0, 6)).toEqual(["--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-user"]);
    expect(invocation.args).not.toContain("--share-net");
    expect(invocation.args).toContain("--seccomp");
    expect(invocation.args).toContain("/home/caplock");
    expect(invocation.args).toContain("--bind");
  });

  it("keeps network:host in the host network namespace", () => {
    const identity = { name: "pkg", version: "1", packageDir: "/project/node_modules/pkg", packageJsonPath: "x" };
    const policy = { ...defaultPolicy(), network: "host" as const };
    const invocation = buildLinuxInvocation({ executable: "/bin/sh", args: ["-c", "echo ok"] }, policy, { projectRoot: "/project", identity });
    expect(invocation.executable).toBe("bwrap");
    expect(invocation.args).toContain("--unshare-user");
    expect(invocation.args).not.toContain("--share-net");
    expect(invocation.args).not.toContain("--unshare-net");
  });
});

// Evaluate the small instruction set emitted by the production filter, so
// syscall numbers, argument offsets and jump distances are checked on both ABIs.
function evaluateFilter(filter: Buffer, arch: number, syscall: number, family = 0): number {
  const data = Buffer.alloc(64); data.writeUInt32LE(syscall, 0); data.writeUInt32LE(arch, 4); data.writeUInt32LE(family, 16);
  let accumulator = 0;
  for (let pc = 0; pc < filter.length; pc += 8) {
    const code = filter.readUInt16LE(pc); const k = filter.readUInt32LE(pc + 4);
    if (code === 0x20) accumulator = data.readUInt32LE(k);
    else if (code === 0x15) pc += 8 * filter.readUInt8(pc + (accumulator === k ? 2 : 3));
    else if (code === 0x06) return k;
    else throw new Error(`Unsupported BPF instruction ${code}`);
  }
  throw new Error("Filter fell through without a verdict");
}

describe("Linux network seccomp filter", () => {
  it.each([
    { name: "x64", arch: 0xc000003e, socketpair: 53, shutdown: 48, read: 0, blocked: [41, 42, 43, 44, 45, 46, 47, 49, 50, 288, 299, 307, 425, 426] },
    { name: "arm64", arch: 0xc00000b7, socketpair: 199, shutdown: 210, read: 63, blocked: [198, 203, 200, 201, 202, 206, 207, 211, 212, 242, 243, 269, 425, 426] },
  ])("allows local socketpairs and shutdown for pipe EOF while retaining network denials on $name", ({ name, arch, socketpair, shutdown, read, blocked }) => {
    const filter = networkDenyFilter(name);
    expect(evaluateFilter(filter, arch, socketpair, 1)).toBe(0x7fff0000); // AF_UNIX
    expect(evaluateFilter(filter, arch, shutdown)).toBe(0x7fff0000);
    for (const family of [0, 2, 10, 30]) expect(evaluateFilter(filter, arch, socketpair, family)).toBe(0x00050001);
    for (const syscall of blocked) expect(evaluateFilter(filter, arch, syscall, 1)).toBe(0x00050001);
    expect(evaluateFilter(filter, arch, read)).toBe(0x7fff0000);
    expect(evaluateFilter(filter, 0, socketpair, 1)).toBe(0x80000000);
  });
  it("fails closed on unsupported architectures", () => {
    expect(() => networkDenyFilter("ia32")).toThrow("unsupported");
  });
});
