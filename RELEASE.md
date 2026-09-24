# CapLock release checklist

Do not publish from automation. Before a v1 release, require a clean Git tree,
all three Node 24 CI platform jobs green (npm and pnpm), a correct version and
changelog, an inspected `npm pack` tarball, `npm run release:check`, the final
package-name availability check, and configured private security reporting.

LICENSE remains an explicit maintainer decision and must be resolved before a
public release. Windows is AppContainer, Linux is Bubblewrap, and macOS is the
native Seatbelt `sandbox-exec` mechanism where Apple still provides it; each
fails closed if its mechanism is absent. Domain allowlists are deliberately
deferred to v1.1.
