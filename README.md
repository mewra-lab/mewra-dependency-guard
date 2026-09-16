<p align="center">
  <img src="./assets/brand/icon.png" width="84" height="84" alt="Mewra Dependency Guard logo" />
</p>

# Mewra Dependency Guard — Supply Chain Scan

<p align="center">
  <a href="https://github.com/mewra-lab/mewra-dependency-guard"><img src="https://img.shields.io/badge/GitHub-mewra--lab%2Fmewra--dependency--guard-181717?logo=github" alt="GitHub repository" /></a>
  <a href="https://github.com/mewra-lab/mewra-dependency-guard/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license" /></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=mewra.mewra-dependency-guard-companion"><img src="https://img.shields.io/badge/VS_Code-Marketplace-007ACC?logo=visualstudiocode" alt="VS Code Marketplace" /></a>
</p>

Mewra Dependency Guard is an open-source VS Code companion extension for [Mewra PreFlight](https://github.com/mewra-lab/mewra-preflight). It registers two diff-scoped dependency-security checks: OSV Scanner plus Trivy scan only changed supported lockfiles, and the existing secure-source guard checks added dependency-source lines for insecure HTTP.

The Marketplace extension ID is `mewra.mewra-dependency-guard-companion`. The
check IDs remain `mewra-dependency-guard:security-scan` and
`dependency-guard:unsafe-source`, so existing PreFlight workspace configuration
continues to work without changes.

## Requirements

- VS Code 1.137 or newer
- Mewra PreFlight 0.5.0 or newer (`mewra.mewra-preflight`)
- One execution mode:
  - `local` (default): both `osv-scanner` and `trivy` available on `PATH`.
  - `docker`: Docker available on `PATH`; images are pulled only after you explicitly select this mode.

## Install

Install Mewra PreFlight v0.5.0 or later first, then install this extension. It activates after VS Code starts and registers `mewra-dependency-guard:security-scan` and `dependency-guard:unsafe-source` with PreFlight.

From the VS Code Marketplace, search **Mewra Dependency Guard** or run:

```bash
code --install-extension mewra.mewra-dependency-guard-companion
```

For a GitHub Release VSIX, use **Extensions: Install from VSIX...**, then reload
the VS Code window. Installing from a VSIX disables automatic Marketplace
updates by default.

When OSV Scanner and Trivy are not configured, the Security Scan row shows a
**Set up** action. It intentionally does not offer PreFlight's generic
package-manager Install action because neither scanner is an npm package named
`security-scan`.

## Using the extension

Dependency Guard is a companion extension, not a separate VS Code sidebar. Its
interface is the **Mewra PreFlight** dashboard, where it contributes the two
dependency checks below. Install and enable Mewra PreFlight first, install
Dependency Guard, then reload the VS Code window.

1. Open a repository and run **Mewra PreFlight: Run Pipeline**.
2. Change a supported lockfile. The **Mewra Dependency Guard — Security Scan**
   row appears only when there is a relevant file in the diff.
3. If the row shows `—`, click **Set up** and choose one execution mode:
   - **Use Docker (recommended)** saves the workspace setting to `docker`.
     Start Docker Desktop, then run the pipeline again.
   - **Install local tools with Homebrew** saves `local` mode and runs
     `brew install osv-scanner trivy` in a visible terminal on macOS after you
     select that option.
   - **Use existing local tools** selects `local` mode when both binaries are
     already on `PATH`.
4. Run the pipeline again. A green check means both scanners completed without
   known vulnerability findings; a warning explains partial or unsuccessful
   scans, and a red result lists detected vulnerabilities.

The same setup picker is available from the Command Palette as **Mewra
Dependency Guard: Set Up Scanner**.

## Configuration

```json
{
  "mewraDependencyGuard.scannerMode": "docker"
}
```

`local` is the default. Docker mode is opt-in: it uses pinned OCI image digests, mounts the opened workspace read-only at `/workspace`, enables a temporary `/tmp` filesystem, drops Linux capabilities, and never mounts the Docker socket or uses privileged mode. Trivy stores its vulnerability database in the Docker-managed `mewra-dependency-guard-trivy-cache` volume; it is never written into the workspace.

The scanners may contact their vulnerability databases. Docker mode is not selected automatically, and neither mode uploads source code from the extension itself.

## Supported files

The check runs only when the current PreFlight diff changes one of these files:

- `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`
- `go.mod`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`
- `Pipfile.lock`, `poetry.lock`, `requirements.txt`, `pubspec.lock`

## Validation

```bash
pnpm install --frozen-lockfile
pnpm validate
```

## Security model

- Scanner commands use fixed argument arrays; no workspace value is interpolated into a shell command.
- Local OSV Scanner, Trivy, and Docker commands resolve only from trusted user or system locations, never `node_modules` or another executable in the opened workspace.
- A changed lockfile must be a regular, non-symlink file that resolves inside the workspace before it is scanned.
- Docker mode rejects workspace paths that cannot be represented as a safe Docker mount argument.
- A missing scanner is `not-configured`; a scanner failure or malformed JSON is a visible warning, never a false pass.
- This extension does not scan secrets or source trees. The secure-source guard examines only added lines in changed dependency manifests and lockfiles; PreFlight's existing secret check remains responsible for that scope.

## License

[MIT](./LICENSE)
