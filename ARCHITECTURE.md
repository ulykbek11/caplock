# Architecture

```text
npm / pnpm install --ignore-scripts
              │
              v
       caplock learn → .caplock/caplock.lock
              │ review
              v
 package manager → caplock-shell → identity / command / policy checks
              │
              v
 Windows AppContainer  |  Linux Bubblewrap  |  macOS Seatbelt
              │
              v
       approved lifecycle command
```

The CLI orchestrates acquisition and approved lifecycle execution. npm or pnpm resolves the dependency graph, but acquisition always disables lifecycle scripts. Before a dependency lifecycle runs, CapLock validates its package identity, lifecycle event, command hash, policy, and package-manager invocation metadata. The shell shim refuses unknown or drifted invocations. The OS backend then enforces filesystem, environment, network, and process restrictions supported on that platform.

Windows uses the trusted x64 helper shipped relative to the package installation. The helper creates a unique AppContainer identity and uses a Job Object for process cleanup. Linux uses Bubblewrap namespaces and a seccomp network-deny filter. macOS generates a Seatbelt profile and invokes `sandbox-exec`; Apple has deprecated this mechanism, so it is supported only where available and where the active contract passes.

`.caplock/config.yaml` stores project defaults. `.caplock/caplock.lock` stores the reviewed lifecycle baseline. These files are not writable from the normal dependency package sandbox and should be reviewed and versioned with the project when shared approvals are required.
