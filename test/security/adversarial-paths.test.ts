import { describe, expect, it } from "vitest";
import { validatePolicyPath } from "../../src/policy.js";
describe("adversarial policy paths", () => {
  for (const candidate of ["$PACKAGE/../../.env", "$PROJECT/../etc/passwd", "$PROJECT//../.env", "/etc/passwd"]) it(`rejects ${candidate}`, () => expect(() => validatePolicyPath(candidate, "/project", "/project/node_modules/pkg")).toThrow());
});
