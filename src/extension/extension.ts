import * as vscode from "vscode";
import { buildSecurityScanCheck } from "../core/security-scan.js";
import type { ScannerMode } from "../core/scanner-command.js";
import { dependencyUnsafeSourceCheck } from "../core/unsafe-source.js";
import type { PreFlightApi } from "../shared/preflight-api.js";

const PREFLIGHT_EXTENSION_ID = "mewra.mewra-preflight";

function isPreFlightApi(value: unknown): value is PreFlightApi {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    candidate.apiVersion === 1 && typeof candidate.registerCheck === "function"
  );
}

function scannerMode(value: unknown): ScannerMode {
  return value === "docker" ? "docker" : "local";
}

async function configureScanner(): Promise<void> {
  const selected = await vscode.window.showQuickPick(
    [
      {
        label: "Use Docker (recommended)",
        description:
          "Pull pinned scanner images; no scanners installed locally",
        mode: "docker" as const,
      },
      {
        label: "Install local tools with Homebrew",
        description: "Install osv-scanner and trivy on this Mac",
        mode: "local" as const,
      },
      {
        label: "Use existing local tools",
        description: "Use osv-scanner and trivy already available on PATH",
        mode: "local" as const,
      },
    ],
    {
      title: "Set up Mewra Dependency Guard",
      placeHolder: "Choose how to run OSV Scanner and Trivy",
    },
  );
  if (!selected) return;

  const config = vscode.workspace.getConfiguration("mewraDependencyGuard");
  await config.update(
    "scannerMode",
    selected.mode,
    vscode.ConfigurationTarget.Workspace,
  );

  if (selected.label === "Use Docker (recommended)") {
    void vscode.window.showInformationMessage(
      "Dependency Guard will use Docker. Start Docker Desktop, then run PreFlight again.",
    );
    return;
  }

  if (selected.label === "Install local tools with Homebrew") {
    if (process.platform !== "darwin") {
      void vscode.window.showInformationMessage(
        "Local mode selected. Install osv-scanner and trivy with your operating system's package manager, then run PreFlight again.",
      );
      return;
    }
    const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    const terminal = vscode.window.createTerminal({
      name: "Mewra Dependency Guard: Install scanners",
      ...(root ? { cwd: root } : {}),
    });
    terminal.show(true);
    terminal.sendText("brew install osv-scanner trivy");
    return;
  }

  void vscode.window.showInformationMessage(
    "Local mode selected. Ensure both osv-scanner and trivy are on PATH, then run PreFlight again.",
  );
}

export async function activate(
  context: vscode.ExtensionContext,
): Promise<void> {
  const extension = vscode.extensions.getExtension(PREFLIGHT_EXTENSION_ID);
  if (!extension) {
    void vscode.window.showWarningMessage(
      "Mewra Dependency Guard requires Mewra PreFlight.",
    );
    return;
  }

  const exported = await extension.activate();
  if (!isPreFlightApi(exported)) {
    void vscode.window.showWarningMessage(
      "Mewra Dependency Guard needs a compatible Mewra PreFlight version.",
    );
    return;
  }

  let registrations: Array<{ dispose(): void }> = [];
  const register = (): void => {
    for (const registration of registrations) registration.dispose();
    const mode = vscode.workspace
      .getConfiguration("mewraDependencyGuard")
      .get<unknown>("scannerMode", "local");
    registrations = [
      exported.registerCheck(
        buildSecurityScanCheck({ mode: scannerMode(mode) }),
      ),
      exported.registerCheck(dependencyUnsafeSourceCheck),
    ];
  };

  register();
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "mewra-dependency-guard.configureScanner",
      configureScanner,
    ),
    {
      dispose: () =>
        registrations.forEach((registration) => registration.dispose()),
    },
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("mewraDependencyGuard.scannerMode")) {
        register();
      }
    }),
  );
}

export function deactivate(): void {}
