# Threat model

## Protected assets

Lifecycle scripts may be able to read developer credentials and project secrets, alter project sources or sibling packages, inherit sensitive environment variables, access the network, or leave child processes running. CapLock treats installed dependency lifecycle scripts as hostile unless their identity and command have been reviewed and recorded.

## Trust boundary

CapLock's trusted parent resolves the package and lifecycle identity, validates the lock entry and policy, constructs a filtered environment, and starts the script through the OS backend. The package manager acquires dependencies with scripts disabled. A script is not run if acquisition interception, identity checks, policy validation, or required backend preflight fails.

- Windows 10/11 x64: classic AppContainer, scoped filesystem ACLs, a sanitized child environment, and Job Object process cleanup.
- Linux: Bubblewrap filesystem/process namespaces and a seccomp filter for `network: none`.
- macOS: Seatbelt through `sandbox-exec` when the mechanism exists and its active contract succeeds.

The reviewed `.caplock/caplock.lock` and project configuration are security-sensitive inputs. Review policy and lockfile changes like code changes. Command, lifecycle-event, version, and available integrity drift require review or are blocked.

## Assumptions and exclusions

CapLock does not protect against kernel vulnerabilities, OS sandbox escapes, root/administrator compromise, malicious firmware, or application behavior after a dependency is installed and run normally. Root-project lifecycle scripts are outside the dependency approval model. Host network access is not domain-filtered. macOS Seatbelt is deprecated by Apple; CapLock fails closed when `sandbox-exec` or its required contract is unavailable.
