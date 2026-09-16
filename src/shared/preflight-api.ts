export type CheckSeverity = "error" | "warning";

export type ChangedFile = {
  path: string;
  status: "added" | "modified" | "deleted" | "renamed";
  oldPath?: string;
};

export type GitDiff = {
  baseBranch: string;
  headBranch: string;
  changedFiles: ChangedFile[];
  rawPatch: string;
};

export type CheckFinding = {
  file: string;
  line: number;
  column?: number;
  message: string;
  rule?: string;
};

export type CheckResult = {
  status: "pass" | "fail" | "warning" | "not-configured" | "skipped";
  findings: CheckFinding[];
  message?: string;
};

export type CommandResult = {
  stdout: string;
  stderr: string;
  code: number;
};

export type PreFlightContext = {
  workspaceRoot: string;
  resolveTool(binName: string): Promise<string | null>;
  resolveTrustedTool?(binName: string): Promise<string | null>;
  runCommand(
    command: string,
    args: string[],
    cwd?: string,
    timeoutMs?: number,
  ): Promise<CommandResult>;
};

export type CheckRunner = {
  readonly id: string;
  readonly label: string;
  readonly severity: CheckSeverity;
  readonly pack: string;
  /** False when the check requires environment setup rather than a package install. */
  readonly installable?: boolean;
  /** Registered command that opens the check's own setup experience. */
  readonly setupCommand?: string;
  appliesTo(diff: GitDiff): boolean;
  run(diff: GitDiff, context: PreFlightContext): Promise<CheckResult>;
};

export type PreFlightApi = {
  readonly apiVersion: 1;
  registerCheck(check: CheckRunner): { dispose(): void };
};
