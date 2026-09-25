# Release checklist

CapLock does not publish automatically. Before tagging or publishing a release:

- Review the full Git diff and confirm the working tree contains only intended release changes.
- Confirm the complete Windows, Ubuntu, and macOS npm/pnpm GitHub Actions matrix is green on the release commit.
- Confirm `package.json`, `package-lock.json`, and `CHANGELOG.md` agree on the release version.
- Confirm `LICENSE` and the `Apache-2.0` package metadata are included in the tarball.
- Verify the npm package name is available and the published package name/version are correct.
- Run `npm run release:check` on a supported native platform and inspect `npm pack --dry-run` output.
- Confirm GitHub private vulnerability reporting is enabled and the guidance in `SECURITY.md` is accurate.
- Inspect the final npm tarball and verify its CLI and platform helper contents.

Only after maintainer review should the release commit be tagged, released on GitHub, and published to npm. Never publish from this checklist or CI automatically.
