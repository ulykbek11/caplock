# Changelog

## [1.0.0] - 2026-09-25

First public release of CapLock’s npm and pnpm dependency lifecycle sandbox.

### Added

- npm and pnpm lifecycle interception with script-disabled dependency acquisition.
- Interactive review and a lockfile for package identity, lifecycle events, command hashes, and policy; drift and unknown scripts fail closed.
- Native Windows x64 AppContainer isolation, filesystem ACL enforcement, sanitized child environments, and Job Object process cleanup.
- Linux x64 Bubblewrap isolation with filesystem and process namespaces and seccomp-enforced `network: none`.
- macOS Seatbelt (`sandbox-exec`) isolation with active contract checks and fail-closed behavior when the mechanism is unavailable.
- Synthetic home and temporary directories, filtered lifecycle environments, package-scoped writable access, and `network: none` / `network: host` policy.
- Active `caplock doctor` security probes and platform release verification for Windows, Linux, and macOS.
- npm package distribution with the trusted Windows x64 native helpers.

### Security and compatibility

- Requires Node.js 24 or later.
- Supports Windows 10/11 x64, Linux x64, and macOS versions with `sandbox-exec` available and a passing active contract (release CI uses `macos-latest`).
- Does not provide domain hostname allowlists, Yarn, Bun, or Windows ARM64 support.
- Linux ARM64 is not included in the v1 release verification matrix.
