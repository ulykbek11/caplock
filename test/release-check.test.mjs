import { describe, expect, it, vi } from "vitest";
import { checkDoctor, parseDoctorJson, parsePackJson } from "../scripts/release-check-doctor.mjs";

describe("release:check doctor JSON handling", () => {
  it("accepts clean JSON and rejects npm script banners instead of parsing mixed output", () => {
    expect(parseDoctorJson('{"ready":true}')).toEqual({ ready: true });
    expect(() => parseDoctorJson(`> caplock-runtime@0.1.0 dev\n{"ready":true}`))
      .toThrow("direct doctor command returned malformed JSON on stdout");
    expect(parsePackJson('[{"filename":"caplock.tgz"}]').filename).toBe("caplock.tgz");
    expect(() => parsePackJson(`> caplock-runtime@0.1.0 prepack\n[{"filename":"caplock.tgz"}]`))
      .toThrow("npm pack returned malformed JSON on stdout");
  });

  it("invokes the built CLI directly and consumes stdout only", () => {
    let invocation;
    const report = checkDoctor({
      root: "C:\\caplock",
      spawn: (executable, args, options) => {
        invocation = { executable, args, options };
        return { status: 0, stdout: '{"ready":true}', stderr: "separate diagnostic" };
      },
    });
    expect(report.ready).toBe(true);
    expect(invocation.executable).toBe(process.execPath);
    expect(invocation.args).toEqual(["C:\\caplock\\dist\\cli.js", "doctor", "--json"]);
    expect(invocation.options.stdio).toBe("pipe");
    expect(invocation.options.shell).toBe(false);
  });

  it("checks exit status before parsing and fails when doctor is not ready", () => {
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      expect(() => checkDoctor({ spawn: () => ({ status: 2, stdout: "not json", stderr: "doctor failed" }) }))
        .toThrow("doctor exited with status 2");
      expect(() => checkDoctor({ spawn: () => ({ status: 0, stdout: '{"ready":false}', stderr: "" }) }))
        .toThrow("doctor reported ready:false");
    } finally { stderr.mockRestore(); }
  });
});
