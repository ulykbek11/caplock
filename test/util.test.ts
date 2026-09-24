import { describe, expect, it } from "vitest";
import { redactText } from "../src/util.js";

describe("diagnostic redaction", () => {
  it("redacts secret assignment and option values", () => {
    expect(redactText("API_TOKEN=do-not-print --password hunter2 SAFE=yes")).toBe("API_TOKEN=[REDACTED] --password [REDACTED] SAFE=yes");
  });
});
