# Security model

CapLock uses a native process boundary: Bubblewrap on Linux, classic AppContainer plus a Job Object on Windows, and Seatbelt on macOS where `sandbox-exec` is available.

These properties are security claims only when the active backend contract passes `caplock doctor` and its platform integration suite. An unavailable or failing backend causes lifecycle execution to fail closed.

It does not protect against kernel or sandbox vulnerabilities, root users, sandbox escapes, malicious native kernel exploits, every persistence technique, root-project scripts, or domain-level network policy. `network: host` deliberately gives the package normal host networking; it is not domain-filtered.

Report vulnerabilities privately to the maintainers before opening a public issue.
