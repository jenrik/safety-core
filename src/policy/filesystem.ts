import { lstatSync, readlinkSync } from "node:fs";

/** A single lstat observation supplied by the harness or a deterministic test. */
export type ExecutableFilesystemEntry =
  | { readonly kind: "file"; readonly executable: boolean }
  | { readonly kind: "directory" }
  | { readonly kind: "symlink"; readonly target: string };

/** Failures are explicit so policy evaluation never guesses from host state. */
export type ExecutableFilesystemFailure = "unavailable" | "permission" | "io" | "mutation";

export type ExecutableFilesystemLookup =
  | { readonly kind: "entry"; readonly entry: ExecutableFilesystemEntry }
  | { readonly kind: "missing" }
  | { readonly kind: "incomplete"; readonly failure: ExecutableFilesystemFailure };

/**
 * Minimal filesystem boundary for executable resolution. Implementations must
 * return lstat observations only; resolving symlinks is deliberately kept in
 * the core so test and production semantics remain identical.
 */
export interface ExecutableFilesystem {
  lstat(path: string): ExecutableFilesystemLookup;
}

/** Default for offline/replay callers. It cannot accidentally inspect the host. */
export const unavailableExecutableFilesystem: ExecutableFilesystem = Object.freeze({
  lstat: () => Object.freeze({ kind: "incomplete", failure: "unavailable" }),
});

/** Explicit production resolver. Adapters opt into this at their live boundary. */
export const nodeExecutableFilesystem: ExecutableFilesystem = Object.freeze({
  lstat(path: string): ExecutableFilesystemLookup {
    try {
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) return Object.freeze({ kind: "entry", entry: Object.freeze({ kind: "symlink", target: readlinkSync(path) }) });
      if (stat.isDirectory()) return Object.freeze({ kind: "entry", entry: Object.freeze({ kind: "directory" }) });
      if (stat.isFile()) return Object.freeze({ kind: "entry", entry: Object.freeze({ kind: "file", executable: (stat.mode & 0o111) !== 0 }) });
      return Object.freeze({ kind: "entry", entry: Object.freeze({ kind: "file", executable: false }) });
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") return Object.freeze({ kind: "missing" });
      if (code === "EACCES" || code === "EPERM") return Object.freeze({ kind: "incomplete", failure: "permission" });
      if (code === "ESTALE") return Object.freeze({ kind: "incomplete", failure: "mutation" });
      return Object.freeze({ kind: "incomplete", failure: "io" });
    }
  },
});
