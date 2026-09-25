# Security policy

CapLock treats dependency lifecycle scripts as untrusted code and runs reviewed npm and pnpm dependency scripts through a native OS sandbox. The required platform checks are active: `caplock doctor`, the platform integration suite, and the release-contract CI matrix exercise the production backend. If a required backend capability or probe is unavailable, CapLock refuses lifecycle execution rather than falling back to an unrestricted process.

The default policy uses a synthetic home and temporary area, filters sensitive environment values, restricts filesystem access, and denies network access. `network: host` grants ordinary host networking without domain filtering. See [THREAT-MODEL.md](THREAT-MODEL.md) for assets, boundaries, and exclusions.

Report security vulnerabilities privately through [GitHub Private Vulnerability Reporting](https://github.com/ulykbek11/caplock/security/advisories/new). Please do not include credentials or exploit details in public issues.
