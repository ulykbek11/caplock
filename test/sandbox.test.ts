import { describe, expect, it } from "vitest";
import { bwrapArgs } from "../src/sandbox.js";
import { defaultPolicy } from "../src/policy.js";
describe("bubblewrap arguments", () => { it("uses namespace and synthetic HOME", () => { const args = bwrapArgs("echo ok", { name: "pkg", version: "1", packageDir: "/project/node_modules/pkg", packageJsonPath: "x" }, "/project", defaultPolicy()); expect(args).toContain("--unshare-net"); expect(args).toContain("/home/caplock"); expect(args).toContain("--bind"); }); });
