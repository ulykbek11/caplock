import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const requested = process.argv[2];
const expected = { windows: "win32", linux: "linux", macos: "darwin" }[requested];
if (!expected || process.platform !== expected) {
  console.error(`verify:${requested ?? "<missing>"} must run on its release platform; current platform is ${process.platform}.`);
  process.exit(1);
}
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const npm = process.platform === "win32" ? "cmd.exe" : "npm";
function invoke(args, capture = false) {
  const result = process.platform === "win32"
    ? spawnSync(npm, ["/d", "/s", "/c", ["npm.cmd", ...args].join(" ")], { cwd: root, stdio: capture ? "pipe" : "inherit", encoding: "utf8", shell: false })
    : spawnSync(npm, args, { cwd: root, stdio: capture ? "pipe" : "inherit", encoding: "utf8", shell: false });
  if (result.error || result.status !== 0) {
    const phase = args[0] === "run" ? `npm run ${args[1]}` : `npm ${args.join(" ")}`;
    const captured = capture ? `${result.stdout ?? ""}\n${result.stderr ?? ""}` : "";
    const lines = capture ? captured.split(/\r?\n/).map((line) => line.trim()).filter(Boolean) : [];
    const marked = lines.filter((line) => /^\s*(?:FAIL\s|AssertionError:|Error:|❯\s|Test Files\s|Tests\s)/u.test(line));
    // Vitest's glyphs/ANSI output vary across hosted runner encodings. If its
    // failure markers aren't recognizable, retain the tail so the release
    // annotation still identifies the actual failing test instead of only
    // reporting that `npm run test` failed.
    const testSummary = (marked.length ? marked : lines.slice(-24)).slice(-24).join(" | ").slice(-3500);
    if (capture) {
      if (result.stdout) process.stdout.write(result.stdout);
      if (result.stderr) process.stderr.write(result.stderr);
    }
    console.error(`::error::verify:${requested} phase failed: ${phase}; ${result.error?.message ?? `exit=${result.status ?? 1}`}${testSummary ? `; ${testSummary}` : ""}`);
    process.exit(result.status ?? 1);
  }
  return result;
}
for (const name of ["lint", "typecheck", "build"]) invoke(["run", name]);
if (requested === "windows") invoke(["run", "native:build"]);
invoke(["run", "test"], true);
invoke(["run", `test:${requested === "windows" ? "windows" : requested}-native`]);
invoke(["run", "test:security"]);
invoke(["run", "test:e2e:npm"]);
invoke(["run", "test:e2e:pnpm"]);
const cli = path.join(root, "dist", "cli.js");
const doctor = spawnSync(process.execPath, [cli, "doctor", "--json"], { cwd: root, encoding: "utf8", shell: false });
if (doctor.status !== 0) { process.stderr.write(doctor.stderr); process.stdout.write(doctor.stdout); process.exit(1); }
try {
  const report = JSON.parse(doctor.stdout);
  if (!report.ready) {
    process.stdout.write(doctor.stdout);
    const failed = Array.isArray(report.checks) ? report.checks.filter((check) => !check.ok).map((check) => `${check.name}: ${check.detail}`).join("; ") : "doctor reported ready:false";
    console.error(`::error::Platform doctor failed: ${failed}`);
    process.exit(1);
  }
} catch { process.stderr.write(`doctor did not return valid JSON:\n${doctor.stdout}\n`); process.exit(1); }
