import type { PreFlightContext } from "../shared/preflight-api.js";

export type ScannerMode = "local" | "docker";
export type ScannerName = "osv" | "trivy";

export type ScannerCommand = {
  scanner: ScannerName;
  command: string;
  args: string[];
};

export const OSV_IMAGE =
  "ghcr.io/google/osv-scanner@sha256:5116601dedc01c1c580eb92371883ec052fc4c13c3fbc109d621a63ac416d475";
export const TRIVY_IMAGE =
  "aquasec/trivy@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f";
const TRIVY_CACHE_VOLUME = "mewra-dependency-guard-trivy-cache";

function dockerSecurityArgs(workspaceRoot: string): string[] | null {
  if (workspaceRoot.includes(",")) return null;
  return [
    "run",
    "--rm",
    "--read-only",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,size=512m",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--mount",
    `type=bind,source=${workspaceRoot},target=/workspace,readonly`,
  ];
}

export async function buildScannerCommands(
  context: PreFlightContext,
  mode: ScannerMode,
  localPath: string,
  containerPath: string,
): Promise<ScannerCommand[]> {
  if (mode === "local") {
    if (!context.resolveTrustedTool) return [];
    const [osv, trivy] = await Promise.all([
      context.resolveTrustedTool("osv-scanner"),
      context.resolveTrustedTool("trivy"),
    ]);
    return [
      ...(osv
        ? [
            {
              scanner: "osv" as const,
              command: osv,
              args: ["scan", "--format", "json", "-L", localPath],
            },
          ]
        : []),
      ...(trivy
        ? [
            {
              scanner: "trivy" as const,
              command: trivy,
              args: ["fs", "--scanners", "vuln", "--format", "json", localPath],
            },
          ]
        : []),
    ];
  }

  const docker = await context.resolveTrustedTool?.("docker");
  const securityArgs = dockerSecurityArgs(context.workspaceRoot);
  if (!docker || !securityArgs) return [];

  return [
    {
      scanner: "osv",
      command: docker,
      args: [
        ...securityArgs,
        OSV_IMAGE,
        "scan",
        "--format",
        "json",
        "-L",
        containerPath,
      ],
    },
    {
      scanner: "trivy",
      command: docker,
      args: [
        ...securityArgs,
        "--mount",
        `type=volume,source=${TRIVY_CACHE_VOLUME},target=/cache`,
        TRIVY_IMAGE,
        "fs",
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--cache-dir",
        "/cache",
        containerPath,
      ],
    },
  ];
}
