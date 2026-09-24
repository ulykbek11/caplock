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

Each supported backend is an enforcement boundary: Windows launches an AppContainer child through the shipped x64 helper and assigns it to a kill-on-close Job Object; Linux uses Bubblewrap namespaces; macOS uses Seatbelt when `sandbox-exec` is present. All use a filtered parent environment and synthetic HOME/temp locations. A missing primitive fails closed. Seatbelt is deprecated by Apple but remains supported only while `sandbox-exec` exists and the native contract passes.

`caplock.lock` is generated approval state. `.caplock/config.yaml` is project configuration; it is intentionally separate so a lifecycle process never controls policy loaded by its parent.
