"use strict";
/* global require */
/* eslint-disable @typescript-eslint/no-require-imports -- Node --require bootstrap is CommonJS. */

// NODE_OPTIONS is parsed before any untrusted lifecycle code.  Keep the native
// compatibility addon behind a normal CommonJS require so loader failures are
// recorded safely instead of being indistinguishable from an absent preload.
const fs = require("node:fs");
const path = require("node:path");

const shim = process.env.CAPLOCK_PIPE_SHIM_PATH;
if (!shim || path.basename(shim) !== "caplock-pipe-shim.node") {
  throw new Error("CapLock trusted pipe shim path is unavailable");
}

const rootPid = process.env.CAPLOCK_PIPE_SHIM_ROOT_PID;
const isRoot = !rootPid || rootPid === String(process.pid);
if (!rootPid) process.env.CAPLOCK_PIPE_SHIM_ROOT_PID = String(process.pid);
if (process.env.CAPLOCK_PIPE_SHIM_DIAGNOSTIC === "1") {
  try { fs.appendFileSync("caplock-pipe-preload-entered.marker", `${process.pid}:${isRoot ? "root" : "nested"}\n`); } catch { /* diagnostic output is best-effort */ }
}

if (isRoot) try {
  require(shim);
} catch (error) {
  // Do not include the addon path or Node's loader text: both can contain
  // machine-specific locations.  The stable error kind is enough to diagnose
  // a staged binary/ACL/loader failure in the fixture.
  try {
    fs.writeFileSync("caplock-pipe-shim-load-error.marker", JSON.stringify({
      name: error && typeof error.name === "string" ? error.name : "Error",
      code: error && typeof error.code === "string" ? error.code : null,
    }));
  } catch { /* diagnostic output is best-effort */ }
  throw error;
}
