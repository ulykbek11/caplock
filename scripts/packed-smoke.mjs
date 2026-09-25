import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";

function invoke(spawn, args, cwd) {
  const result = spawn(process.execPath, args, { cwd, encoding: "utf8", shell: false });
  if (result.error || result.status !== 0) {
    const message = result.error?.message ?? `exit=${result.status ?? 1}`;
    throw new Error(`packed CapLock command failed (${args.slice(1).join(" ")}): ${message}\n${result.stderr ?? ""}`);
  }
  return result.stdout ?? "";
}

export function smokePackedCli({ consumerRoot, packageName, expectedVersion, spawn = spawnSync }) {
  const cli = path.join(consumerRoot, "node_modules", packageName, "dist", "cli.js");
  if (!existsSync(cli)) throw new Error(`packed CapLock CLI is missing: ${cli}`);
  const binDirectory = path.join(consumerRoot, "node_modules", ".bin");
  const suffix = process.platform === "win32" ? ".cmd" : "";
  for (const name of ["caplock", "caplock-shell"]) {
    const launcher = path.join(binDirectory, `${name}${suffix}`);
    if (!existsSync(launcher)) throw new Error(`packed ${name} launcher is missing: ${launcher}`);
  }
  const version = invoke(spawn, [cli, "version"], consumerRoot);
  if (!version.includes(expectedVersion)) throw new Error(`packed caplock version output did not include ${expectedVersion}`);
  const help = invoke(spawn, [cli, "--help"], consumerRoot);
  if (!/Usage:\s+caplock\b/u.test(help)) throw new Error("packed caplock --help did not show the CLI usage");
  const json = invoke(spawn, [cli, "doctor", "--json"], consumerRoot);
  let doctor;
  try { doctor = JSON.parse(json); }
  catch { throw new Error("packed caplock doctor returned malformed JSON"); }
  if (doctor.ready !== true) throw new Error("packed caplock doctor reported ready:false");
  invoke(spawn, [cli, "init"], consumerRoot);
  if (!existsSync(path.join(consumerRoot, ".caplock", "config.yaml")) || !existsSync(path.join(consumerRoot, ".caplock", "caplock.lock"))) {
    throw new Error("packed caplock init did not create the project configuration and lockfile");
  }
  return { cli, doctor };
}
