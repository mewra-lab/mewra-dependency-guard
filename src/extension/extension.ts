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
