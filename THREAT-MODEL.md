# Threat model

Assets include developer HOME secrets, project secret files, environment values, project sources, sibling dependencies, and host network/process visibility. A dependency lifecycle script is treated as hostile.

The trust boundary is the selected native backend. CapLock's trusted parent selects the package identity and immutable approval entry before the dependency starts. Linux uses Bubblewrap, Windows uses an AppContainer child with a temporary unique identity, and macOS uses a generated Seatbelt profile when available. A backend that cannot establish or verify its required policy fails closed.

Out of scope: kernel and sandbox vulnerabilities, root attackers, malicious hardware/firmware, application behavior after installation, and domain-level network filtering. Host networking is an explicit capability and is not domain-filtered.
