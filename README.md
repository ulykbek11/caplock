# CapLock

> Sandbox npm install scripts before they touch your machine.

`npm` can decide whether a dependency is allowed to run an install script.
CapLock controls what that script can access when it runs.

CapLock is a local-first CLI for running reviewed npm dependency lifecycle scripts inside an operating-system sandbox. It sends no project data or source code anywhere.

## Platform status

| Platform | Backend | Status |
| --- | --- | --- |
| Linux | Bubblewrap | native backend; active verification required by `doctor` |
| Windows 10/11 x64 | classic AppContainer + Job Object | native helper and production self-test; full security contract remains verification-gated |
| macOS | Seatbelt (`sandbox-exec`) | native profile generation; full security contract remains verification-gated |

CapLock never substitutes an unrestricted process when a native backend is unavailable or its required verification fails.

## Quick start

```bash
npm install -g caplock-runtime
caplock doctor
caplock init
caplock learn
caplock install
```

Linux users also install `bubblewrap` and `strace` (for example, `sudo apt-get install bubblewrap strace`). Windows users do not need WSL; `doctor` reports the native Windows backend and whether its native helper is ready.

`learn` records the installed `preinstall`, `install`, and `postinstall` commands in `.caplock/caplock.lock`. A changed command or version is refused until reviewed and learned again.

## How it works

`caplock install` first invokes `npm install --ignore-scripts`. It then proves npm's `script-shell` interception with a harmless canary. Only then does `npm rebuild` run, with each approved dependency lifecycle command dispatched through Bubblewrap.

The intended default is a writable package and sandbox temp directory, a synthetic empty HOME, filtered environment, and no network. `caplock doctor` is the authority for whether that contract is actively verified on the current machine; do not treat an unverified platform as protected.

## Threat model and limits

See [SECURITY.md](SECURITY.md). CapLock reduces the authority given to dependency lifecycle scripts; it does not guarantee containment against kernel or Bubblewrap vulnerabilities.

## Commands

`caplock doctor`, `caplock learn [package]`, `caplock install [npm arguments]`, `caplock inspect`, `caplock diff`, and `caplock ci`.

## CI

```yaml
- run: sudo apt-get update && sudo apt-get install -y bubblewrap strace
- run: npm install -g caplock-runtime
- run: caplock ci
```

## Roadmap

Domain-level networking is not implemented. `network: host` permits normal host networking when the native backend supports it.
