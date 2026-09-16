# Release guide

The first release is `v0.1.0`.

1. Confirm the target branch is `main` and `pnpm validate` passes.
2. Verify `package.json` has the intended version.
3. Commit and merge the release-ready change to `main`.
4. Create an annotated tag with the matching version, for example `v0.1.0`, and push it.
5. The GitHub Actions release workflow validates, packages the versioned VSIX, generates `SHA256SUMS.txt`, and publishes the GitHub Release.

## v0.1.1

- Requires Mewra PreFlight 0.5.0 or later.
- Marks the OSV/Trivy Security Scan as environment-managed so PreFlight does not incorrectly offer to install a `security-scan` npm package.
- Adds guided scanner setup and normalized OSV advisory metadata: severity,
  CVSS score, fixed version, and advisory URL when supplied by OSV.

Release notes for `v0.1.0` should state that this is the initial companion extension, requires Mewra PreFlight v0.4.0 / API v1, scans changed supported lockfiles with OSV Scanner and Trivy, preserves the insecure dependency-source guard, and offers local plus explicitly selected hardened Docker execution.
