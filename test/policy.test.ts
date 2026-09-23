import { describe, expect, it } from "vitest";
import { filterEnvironment, isSensitiveProjectPath, substitutePolicyPath, validatePolicyPath } from "../src/policy.js";
import { sha256 } from "../src/util.js";
describe("policy", () => {
  it("blocks sensitive project paths", () => { expect(isSensitiveProjectPath(".env")).toBe(true); expect(isSensitiveProjectPath("nested/.env.local")).toBe(true); expect(isSensitiveProjectPath("src/index.js")).toBe(false); });
  it("accepts only contained policy paths", () => { expect(substitutePolicyPath("$PACKAGE/out", "/project", "/project/node_modules/a")).toBe("/project/node_modules/a/out"); expect(substitutePolicyPath("$TMP/out", "/project", "/project/node_modules/a", { tmp: "/tmp" })).toBe("/tmp/out"); expect(() => validatePolicyPath("$PROJECT/../secret", "/project", "/project/node_modules/a")).toThrow("escapes"); expect(() => validatePolicyPath("/etc/passwd", "/project", "/project/node_modules/a")).toThrow("must start"); });
  it("removes secrets from environment", () => { const env = filterEnvironment({ CAPLOCK_TEST_SECRET: "no", SAFE: "yes", npm_lifecycle_event: "install" }, ["SAFE"]); expect(env.CAPLOCK_TEST_SECRET).toBeUndefined(); expect(env.SAFE).toBe("yes"); expect(env.npm_lifecycle_event).toBe("install"); });
  it("hashes scripts deterministically", () => expect(sha256("node install.js")).toBe(sha256("node install.js")));
});
