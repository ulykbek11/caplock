# Architecture

```text
npm install --ignore-scripts
             |
             v
       CapLock approval lockfile
             |
             v
npm rebuild -> caplock-shell -> selected native backend -> lifecycle command
```

The CLI owns package-manager orchestration and project state. The shell shim identifies the invoking dependency, loads its previously approved lifecycle entry, and refuses unknown or drifted commands. Backend selection is automatic: Windows uses the native helper, Linux uses Bubblewrap, and macOS uses Seatbelt when available. A backend that cannot meet the requested policy stops execution instead of falling back to the host process.

Linux is currently the fully implemented enforcement boundary: it exposes a read-only dependency tree, overlays the executing package read/write, creates `/tmp` and synthetic HOME, filters environment variables, and creates a network namespace by default. Windows and macOS backends are deliberately fail-closed until their filesystem and network boundaries are complete.

`caplock.lock` is generated approval state. `.caplock/config.yaml` is project configuration; it is intentionally separate so a lifecycle process never controls policy loaded by its parent.
