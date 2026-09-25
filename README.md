# CapLock

A cross-platform runtime sandbox for npm and pnpm dependency lifecycle scripts.

Dependencies can execute `preinstall`, `install`, and `postinstall` scripts with your user privileges. CapLock acquires dependencies with scripts disabled, lets you review and lock approved lifecycle commands, then runs those commands inside a native operating-system sandbox.

## Why CapLock

An install script can otherwise read project `.env` files and your home directory, inherit sensitive environment values, modify project or sibling-package files, use the network, or leave child processes running. CapLock limits lifecycle-script access according to the reviewed policy and stops rather than running a script unrestricted when its policy cannot be enforced.

## Quick start

Install CapLock once:

```sh
npm install --global caplock-runtime
```

Make sure both npm and pnpm are installed or enabled. `caplock doctor` checks the backend and both supported package-manager runners before reporting ready.

From an npm project, acquire dependencies without running their scripts, then review and approve the lifecycle baseline:

```sh
npm install --ignore-scripts
caplock doctor
caplock init
caplock learn
caplock install
```

`caplock learn` displays each discovered package, version, integrity (when available), lifecycle event and command, along with its proposed network and filesystem policy. It prompts `Save this policy? [y/N]`; the default is no. Use `caplock learn --yes` only when approval is intentional in a non-interactive environment.

For pnpm, use the corresponding acquisition command:

```sh
pnpm install --ignore-scripts
caplock doctor
caplock init
caplock learn
caplock install
```

CapLock detects pnpm projects from `pnpm-lock.yaml`. Review the generated `.caplock/caplock.lock` and `.caplock/config.yaml`, then commit them if teammates and CI should share the approved baseline. Subsequent `caplock install` runs acquire with scripts disabled, verify lifecycle interception, and run only approved dependency lifecycle commands through the sandbox.

## How it works

```text
npm / pnpm install --ignore-scripts
              │ dependency acquisition, scripts disabled
              ▼
       caplock learn → reviewed .caplock/caplock.lock
              │
              ▼
  package manager → CapLock lifecycle shell
              │ identity / event / command validation
              ▼
      native OS sandbox → approved lifecycle command
```

The package manager resolves and acquires dependencies. CapLock validates the installed package identity, lifecycle event, command hash, integrity where available, and policy before invoking the script inside the selected OS backend.

## Platform support

| Platform | Runtime boundary | Release contract |
| --- | --- | --- |
| Windows 10/11 x64 | Classic AppContainer, filesystem ACLs, filtered environment and Job Object | Native helper; active launch, filesystem, environment, network and cleanup checks |
| Linux x64 (release-tested) | Bubblewrap namespaces with seccomp network denial for `network: none` | Active filesystem, environment, network and process checks; install `bubblewrap` and `strace`, and enable unprivileged user namespaces |
| macOS | Seatbelt via Apple’s `sandbox-exec` | Active filesystem, environment and network checks; execution fails closed if the mechanism or contract is unavailable |

Apple has deprecated `sandbox-exec`; CapLock uses it only where available and requires its active contract to pass. CI currently validates the macOS version provided by `macos-latest`; other versions must pass `caplock doctor`. Linux ARM64 is not included in the v1 release matrix. Windows ARM64 is not supported in v1. The supported package managers are npm and pnpm. Node.js 24 or later is required.

## Security model

The default policy provides a synthetic home and temporary directory, filters the child environment, restricts filesystem access to the target package and approved paths, and denies networking. `network: host` deliberately permits normal host networking; domain-level filtering is not provided. Windows uses a Job Object for child-process cleanup; Linux uses Bubblewrap process isolation and parent-death behavior. macOS process behavior is bounded by Seatbelt and the host process timeout/cleanup path, not a Windows-style Job Object.

CapLock is a least-authority boundary for dependency lifecycle scripts, not a guarantee against every attack. It does not protect against kernel or sandbox vulnerabilities, a root/administrator attacker, or malicious behavior after a dependency is installed and used by the application. Root-project lifecycle scripts are outside the dependency approval model.

Details: [Security policy](SECURITY.md), [Threat model](THREAT-MODEL.md), and [Architecture](ARCHITECTURE.md).

## Policy and lockfile

- `.caplock/config.yaml` stores project defaults such as the network mode and lifecycle timeout.
- `.caplock/caplock.lock` stores reviewed package identity, integrity when available, lifecycle event, command hash, and policy.

Unknown packages or events, invalid policies, and identity or command drift fail closed. Review changes with `caplock diff`; use `caplock learn` to inspect and approve a new baseline. Treat the lockfile as security-sensitive review input.

## Commands

- `caplock doctor [--json]` — actively check backend readiness and required security probes.
- `caplock init` — create the default configuration and approval lockfile.
- `caplock learn [package] [--yes] [--network none|host]` — review and record installed lifecycle scripts.
- `caplock install [manager arguments]` — acquire with scripts disabled and execute approved lifecycles through the sandbox.
- `caplock inspect` — list approved lifecycle entries.
- `caplock diff` — find installed lifecycle entries that need review.
- `caplock audit` — report entries with host networking or additional writable paths.
- `caplock reset` — remove local CapLock configuration and approvals.
- `caplock explain <topic> [name]` — explain policy behavior.
- `caplock version` — print version and runtime/backend diagnostics.
- `caplock ci` — perform the package-manager CI install flow; requires a reviewed lockfile in the checkout.

## CI usage

Commit the reviewed `.caplock/` files with the project. On Linux, install Bubblewrap and strace before running CapLock:

```yaml
- uses: actions/setup-node@v4
  with:
    node-version: 24
- run: corepack enable
- run: corepack prepare pnpm@10.17.1 --activate
- run: sudo apt-get update && sudo apt-get install -y bubblewrap strace apparmor-profiles apparmor-utils
- run: sudo apparmor_parser -r /usr/share/apparmor/extra-profiles/bwrap-userns-restrict
- run: npm install --global caplock-runtime
- run: caplock doctor
- run: caplock ci
```

Use `pnpm install --ignore-scripts` before review and the same `caplock ci` command for a pnpm project. CI should fail when `doctor` or lifecycle policy validation fails.

## Development

Use Node.js 24 or later:

```sh
npm ci
npm test
npm run lint
npm run typecheck
npm run build
npm run verify:linux   # on Linux
npm run verify:windows # on Windows x64
npm run verify:macos   # on macOS
```

Each `verify:<platform>` command is intended to run on its matching native OS and includes the platform contract, doctor, and npm/pnpm E2E checks. See [Contributing](CONTRIBUTING.md) for security-test expectations.

## Limitations

V1 supports only npm, pnpm, and the `none`/`host` network modes. Domain hostname allowlists, Yarn, Bun, Linux ARM64 release validation, Windows ARM64, and GUI tooling are not supported. Host networking is not domain-filtered. See the [threat model](THREAT-MODEL.md) for additional boundaries and exclusions.
