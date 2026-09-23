# Release guide

The first release is `v0.1.0`.

1. Confirm the target branch is `main` and `pnpm validate` passes.
2. Verify `package.json` has the intended version.
3. Commit and merge the release-ready change to `main`.
4. Create an annotated tag with the matching version, for example `v0.1.0`, and push it.
5. The GitHub Actions release workflow validates, packages the versioned VSIX, generates `SHA256SUMS.txt`, and publishes the GitHub Release.

`pnpm package` writes local package output to `artifacts/`. The directory is
tracked only with a placeholder; VSIX files and checksums are ignored and the
directory is excluded from the extension package. GitHub Releases remain the
distributable archive of record.

## v0.5.0

- Adds opt-in `mewraDependencyGuard.securityScanScope: "workspace"` and a
  **Configure Scan Scope** command so regular PreFlight runs can scan all
  supported lockfiles even with no Git changes.
- Keeps diff-scoped scanning as the default and documents transparent disable,
  warning, and `.preflightignore` exceptions.

## v0.4.0

- Adds **Mewra Dependency Guard: Run Full Dependency Scan** for an intentional
  workspace-wide OSV/Trivy audit when no lockfile is changed.
- Keeps the PreFlight Security Scan diff-scoped and keeps full-scan results out
  of pipeline/PR gating.
- Makes multi-root selection explicit, excludes generated/dependency paths and
  symlinks, caps discovery at 32 lockfiles, and uses fixed commands resolved
  only from trusted user/system locations.

## v0.3.0

- Uses the Marketplace extension identity
  `mewra.mewra-dependency-guard-companion`, replacing the unpublished
  `-vscode` candidate with a name that reflects its companion role.
- Keeps the display name **Mewra Dependency Guard — Supply Chain Scan** distinct
  from the removed listing.

## v0.2.1

- Superseded before Marketplace publication by v0.3.0.

## v0.2.0

- Publishes the VSIX as `mewra-dependency-guard-vscode-0.2.0.vsix` under the then-proposed Marketplace identity
  `mewra.mewra-dependency-guard-vscode` after the original Marketplace record
  was removed and its name remained reserved.
- Keeps the repository, display name, command IDs, configuration keys, and
  PreFlight check IDs unchanged, so no `.mewra-preflight.json` migration is
  required.
- Adds Marketplace-facing README branding, install instructions, and links.

## v0.1.3

- Adds the shared Mewra Marketplace icon used by Mewra Pounce and PreFlight.

## v0.1.2

- Replaces the unsupported Visual Studio Marketplace `Security` category with
  the supported `Testing` category so the VSIX can be published.

## v0.1.1

- Requires Mewra PreFlight 0.5.0 or later.
- Marks the OSV/Trivy Security Scan as environment-managed so PreFlight does not incorrectly offer to install a `security-scan` npm package.
- Adds guided scanner setup and normalized OSV advisory metadata: severity,
  CVSS score, fixed version, and advisory URL when supplied by OSV.

Release notes for `v0.1.0` should state that this is the initial companion extension, requires Mewra PreFlight v0.4.0 / API v1, scans changed supported lockfiles with OSV Scanner and Trivy, preserves the insecure dependency-source guard, and offers local plus explicitly selected hardened Docker execution.
