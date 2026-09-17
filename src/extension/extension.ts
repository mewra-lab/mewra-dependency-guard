import * as vscode from "vscode";
import { discoverSupportedLockfiles } from "../core/lockfiles.js";
import { createScannerContext } from "../core/scanner-context.js";
import {
  buildSecurityScanCheck,
  runSecurityScan,
} from "../core/security-scan.js";
import type { ScannerMode } from "../core/scanner-command.js";
import { dependencyUnsafeSourceCheck } from "../core/unsafe-source.js";
import type { CheckResult, PreFlightApi } from "../shared/preflight-api.js";

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

function configuredScannerMode(): ScannerMode {
  return scannerMode(
    vscode.workspace
      .getConfiguration("mewraDependencyGuard")
      .get<unknown>("scannerMode", "local"),
  );
}

async function selectWorkspaceRoot(): Promise<string | undefined> {
  const folders = vscode.workspace.workspaceFolders ?? [];
  if (folders.length === 0) {
    void vscode.window.showWarningMessage(
      "Open a workspace folder before running a full dependency scan.",
    );
    return undefined;
  }

  const activeFolder = vscode.window.activeTextEditor
    ? vscode.workspace.getWorkspaceFolder(
        vscode.window.activeTextEditor.document.uri,
      )
    : undefined;
  if (activeFolder) return activeFolder.uri.fsPath;
  if (folders.length === 1) return folders[0]?.uri.fsPath;

  const selected = await vscode.window.showQuickPick(
    folders.map((folder) => ({
      label: folder.name,
      description: folder.uri.fsPath,
      root: folder.uri.fsPath,
    })),
    {
      title: "Full Dependency Scan",
      placeHolder: "Choose the workspace folder to scan",
    },
  );
  return selected?.root;
}

function writeFullScanResult(
  output: vscode.OutputChannel,
  workspaceRoot: string,
  files: string[],
  result: CheckResult,
): void {
  output.clear();
  output.appendLine("Mewra Dependency Guard — Full Dependency Scan");
  output.appendLine(`Workspace: ${workspaceRoot}`);
  output.appendLine(`Lockfiles: ${files.length}`);
  for (const file of files) output.appendLine(`  - ${file}`);
  output.appendLine("");
  output.appendLine(`Status: ${result.status.toUpperCase()}`);
  if (result.message) output.appendLine(result.message);

  if (result.findings.length > 0) {
    output.appendLine("");
    output.appendLine(`Findings (${result.findings.length}):`);
    for (const finding of result.findings) {
      const metadata = finding.metadata ?? {};
      const packageLabel = metadata.packageName
        ? `${metadata.packageName}${metadata.installedVersion ? `@${metadata.installedVersion}` : ""}`
        : finding.message;
      const details = [
        metadata.scanner,
        metadata.severity ? `severity ${metadata.severity}` : undefined,
        metadata.cvss ? `CVSS ${metadata.cvss}` : undefined,
        metadata.fixedVersion ? `fixed ${metadata.fixedVersion}` : undefined,
      ].filter((value): value is string => Boolean(value));
      output.appendLine(`- ${finding.rule ?? "advisory"}: ${packageLabel}`);
      output.appendLine(
        `  ${finding.file}${details.length > 0 ? ` — ${details.join(", ")}` : ""}`,
      );
      if (metadata.advisoryUrl) output.appendLine(`  ${metadata.advisoryUrl}`);
    }
  }
}

async function runFullDependencyScan(
  output: vscode.OutputChannel,
): Promise<void> {
  const workspaceRoot = await selectWorkspaceRoot();
  if (!workspaceRoot) return;

  const discovery = await discoverSupportedLockfiles(workspaceRoot);
  if (discovery.truncated) {
    void vscode.window.showWarningMessage(
      "Full Dependency Scan found more than 32 supported lockfiles. Narrow the workspace before scanning.",
    );
    return;
  }
  if (discovery.files.length === 0) {
    output.clear();
    output.appendLine("Mewra Dependency Guard — Full Dependency Scan");
    output.appendLine(`Workspace: ${workspaceRoot}`);
    output.appendLine("No supported lockfiles found.");
    output.show(true);
    void vscode.window.showInformationMessage(
      "No supported lockfiles found in the selected workspace.",
    );
    return;
  }

  const result = await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Mewra Dependency Guard: scanning ${discovery.files.length} lockfile${discovery.files.length === 1 ? "" : "s"}`,
      cancellable: false,
    },
    () =>
      runSecurityScan(
        discovery.files,
        createScannerContext(workspaceRoot),
        { mode: configuredScannerMode() },
        "workspace",
      ),
  );
  writeFullScanResult(output, workspaceRoot, discovery.files, result);
  output.show(true);

  if (result.status === "not-configured") {
    const action = await vscode.window.showWarningMessage(
      result.message ?? "Security scanners are not configured.",
      "Set Up Scanner",
      "Show Results",
    );
    if (action === "Set Up Scanner") {
      await vscode.commands.executeCommand(
        "mewra-dependency-guard.configureScanner",
      );
    } else if (action === "Show Results") {
      output.show(true);
    }
    return;
  }

  const message = result.message ?? "Full dependency scan completed.";
  if (result.status === "fail") {
    const action = await vscode.window.showErrorMessage(
      message,
      "Show Results",
    );
    if (action === "Show Results") output.show(true);
  } else if (result.status === "warning") {
    const action = await vscode.window.showWarningMessage(
      message,
      "Show Results",
    );
    if (action === "Show Results") output.show(true);
  } else {
    void vscode.window
      .showInformationMessage(message, "Show Results")
      .then((action) => {
        if (action === "Show Results") output.show(true);
      });
  }
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
    registrations = [
      exported.registerCheck(
        buildSecurityScanCheck({ mode: configuredScannerMode() }),
      ),
      exported.registerCheck(dependencyUnsafeSourceCheck),
    ];
  };

  register();
  const output = vscode.window.createOutputChannel("Mewra Dependency Guard");
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "mewra-dependency-guard.configureScanner",
      configureScanner,
    ),
    vscode.commands.registerCommand(
      "mewra-dependency-guard.fullDependencyScan",
      () => runFullDependencyScan(output),
    ),
    output,
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
