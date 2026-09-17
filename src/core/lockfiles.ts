import { type Dirent } from "node:fs";
import { lstat, readdir, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import type { ChangedFile } from "../shared/preflight-api.js";

const SUPPORTED_LOCKFILES = new Set([
  "bun.lock",
  "composer.lock",
  "Cargo.lock",
  "Gemfile.lock",
  "go.mod",
  "package-lock.json",
  "Pipfile.lock",
  "pnpm-lock.yaml",
  "poetry.lock",
  "pubspec.lock",
  "requirements.txt",
  "yarn.lock",
]);

const EXCLUDED_DIRECTORIES = new Set([
  ".git",
  ".next",
  ".pnpm-store",
  ".turbo",
  ".venv",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "vendor",
  "venv",
]);

const MAX_FULL_SCAN_LOCKFILES = 32;
const MAX_FULL_SCAN_DEPTH = 12;

export type LockfileDiscovery = {
  files: string[];
  truncated: boolean;
};

export function isSupportedLockfile(path: string): boolean {
  return SUPPORTED_LOCKFILES.has(path.split("/").at(-1) ?? path);
}

export function changedLockfiles(files: ChangedFile[]): string[] {
  return files
    .filter(
      (file) => file.status !== "deleted" && isSupportedLockfile(file.path),
    )
    .map((file) => file.path);
}

/**
 * Finds supported dependency manifests for the user-invoked full scan.
 *
 * This deliberately skips generated/dependency directories and symbolic links.
 * The regular-file and realpath validation is repeated immediately before each
 * scanner command by resolveWorkspaceFile.
 */
export async function discoverSupportedLockfiles(
  workspaceRoot: string,
): Promise<LockfileDiscovery> {
  const files: string[] = [];
  let truncated = false;

  async function visit(directory: string, depth: number): Promise<void> {
    if (truncated || depth > MAX_FULL_SCAN_DEPTH) return;

    let entries: Dirent[];
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries.sort((left, right) =>
      left.name.localeCompare(right.name),
    )) {
      if (truncated || entry.isSymbolicLink()) continue;
      const entryPath = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRECTORIES.has(entry.name)) {
          await visit(entryPath, depth + 1);
        }
        continue;
      }
      if (!entry.isFile() || !isSupportedLockfile(entry.name)) continue;

      if (files.length >= MAX_FULL_SCAN_LOCKFILES) {
        truncated = true;
        return;
      }
      const workspacePath = relative(workspaceRoot, entryPath)
        .split(sep)
        .join("/");
      files.push(workspacePath);
    }
  }

  await visit(workspaceRoot, 0);
  return { files, truncated };
}

function isInsideWorkspace(workspaceRoot: string, candidate: string): boolean {
  const workspaceRelative = relative(workspaceRoot, candidate);
  return (
    workspaceRelative !== "" &&
    workspaceRelative !== ".." &&
    !workspaceRelative.startsWith(`..${sep}`) &&
    !isAbsolute(workspaceRelative)
  );
}

export async function resolveWorkspaceFile(
  workspaceRoot: string,
  workspacePath: string,
): Promise<string | null> {
  const absolutePath = resolve(workspaceRoot, workspacePath);
  if (!isInsideWorkspace(workspaceRoot, absolutePath)) return null;

  try {
    const metadata = await lstat(absolutePath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) return null;

    const [realWorkspaceRoot, realFile] = await Promise.all([
      realpath(workspaceRoot),
      realpath(absolutePath),
    ]);
    return isInsideWorkspace(realWorkspaceRoot, realFile) ? realFile : null;
  } catch {
    return null;
  }
}

export function dockerWorkspacePath(workspacePath: string): string | null {
  if (
    workspacePath.startsWith("/") ||
    workspacePath.split("/").includes("..")
  ) {
    return null;
  }
  return `/workspace/${workspacePath}`;
}
