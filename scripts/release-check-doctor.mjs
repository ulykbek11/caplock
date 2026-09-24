import { spawnSync } from "node:child_process";
import path from "node:path";

export function parseDoctorJson(stdout) {
  let report;
  try {
    report = JSON.parse(stdout);
  } catch {
    throw new Error("release:check: direct doctor command returned malformed JSON on stdout.");
  }
  if (!report || typeof report !== "object" || typeof report.ready !== "boolean") {
    throw new Error("release:check: direct doctor JSON is missing the boolean ready field.");
  }
  return report;
}

export function parsePackJson(stdout) {
  let contents;
  try {
    contents = JSON.parse(stdout);
  } catch {
    throw new Error("release:check: npm pack returned malformed JSON on stdout.");
  }
  if (!Array.isArray(contents) || typeof contents[0]?.filename !== "string") {
    throw new Error("release:check: npm pack JSON is missing the tarball filename.");
  }
  return contents[0];
}

export function checkDoctor({ root = process.cwd(), spawn = spawnSync } = {}) {
  const cli = path.join(root, "dist", "cli.js");
  const result = spawn(process.execPath, [cli, "doctor", "--json"], {
    cwd: root,
    encoding: "utf8",
    shell: false,
    stdio: "pipe",
  });
  if (result.error) throw new Error(`release:check: could not run doctor: ${result.error.message}`);
  if (result.status !== 0) {
    if (result.stderr) process.stderr.write(result.stderr);
    throw new Error(`release:check: doctor exited with status ${result.status ?? "unknown"}.`);
  }
  const report = parseDoctorJson(result.stdout ?? "");
  if (!report.ready) {
    if (result.stderr) process.stderr.write(result.stderr);
    throw new Error("release:check: doctor reported ready:false.");
  }
  return report;
}
