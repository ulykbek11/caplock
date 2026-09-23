import { describe, expect, it } from "vitest";
import { buildLinuxArgs } from "../src/sandbox/linux.js";
import { defaultPolicy } from "../src/policy.js";
describe("production Bubblewrap arguments", () => { it("uses namespace and synthetic HOME", () => { const identity = { name: "pkg", version: "1", packageDir: "/project/node_modules/pkg", packageJsonPath: "x" }; const args = buildLinuxArgs({ executable: "/bin/sh", args: ["-c", "echo ok"] }, defaultPolicy(), { projectRoot: "/project", identity }); expect(args).toContain("--unshare-net"); expect(args).toContain("/home/caplock"); expect(args).toContain("--bind"); }); });
