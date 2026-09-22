import type { BindingValue } from "../bash/environment.js";
import type {
  ExecutableFilesystem,
  ExecutableFilesystemFailure,
  ExecutableFilesystemLookup,
} from "./filesystem.js";

export type ExecutableIdentityFailure =
  | { readonly kind: "path-unavailable" }
  | { readonly kind: "path-candidate-incomplete"; readonly path: string; readonly failure: ExecutableFilesystemFailure }
  | { readonly kind: "filesystem"; readonly path: string; readonly failure: ExecutableFilesystemFailure }
  | { readonly kind: "not-found" }
  | { readonly kind: "not-executable"; readonly path: string }
  | { readonly kind: "directory"; readonly path: string }
  | { readonly kind: "broken-symlink"; readonly path: string }
  | { readonly kind: "symlink-loop"; readonly path: string }
  | { readonly kind: "symlink-depth"; readonly path: string };

/**
 * A command spelling retains basename information even when its location is
 * incomplete. Path-dependent fields are present only after full resolution.
 */
export type ExecutableIdentity =
  | {
    readonly qualification: "known";
    readonly spelling: string;
    readonly basename: string;
    readonly selectedPath: string;
    readonly canonicalTarget: string;
    /** Ordered symlink sources followed by the canonical target. */
    readonly chain: readonly string[];
  }
  | {
    readonly qualification: "incomplete";
    readonly spelling: string;
    readonly basename: string;
    readonly selectedPath?: string;
    readonly chain: readonly string[];
    readonly failure: ExecutableIdentityFailure;
  }
  | {
    readonly qualification: "unknown";
    readonly reason: "unresolved-spelling";
  };

export const MAX_EXECUTABLE_SYMLINKS = 40;

/** Resolve a known command spelling using shell PATH ordering and no ambient I/O. */
export function resolveExecutableIdentity(
  spelling: string,
  environment: Readonly<Record<string, BindingValue>>,
  cwd: string,
  filesystem: ExecutableFilesystem,
): ExecutableIdentity {
  const basename = pathBasename(spelling);
  if (spelling.includes("/")) return resolveDirect(spelling, basename, cwd, filesystem);

  const path = environment.PATH;
  if (!path || path.kind !== "known") return incomplete(spelling, basename, [], { kind: "path-unavailable" });
  let lastFailure: ExecutableIdentityFailure = { kind: "not-found" };
  for (const entry of path.value.split(":")) {
    const selectedPath = joinPath(entry === "" ? cwd : absoluteFrom(cwd, entry), spelling);
    const candidate = resolveCandidate(selectedPath, filesystem);
    if (candidate.kind === "known") return known(spelling, basename, selectedPath, candidate.canonicalTarget, candidate.chain);
    if (candidate.failure.kind === "filesystem" || candidate.failure.kind === "symlink-loop" || candidate.failure.kind === "symlink-depth") {
      // An earlier unresolved candidate may be the command the shell reaches.
      return incomplete(spelling, basename, candidate.chain, {
        kind: "path-candidate-incomplete",
        path: selectedPath,
        failure: candidate.failure.kind === "filesystem" ? candidate.failure.failure : "io",
      }, selectedPath);
    }
    lastFailure = candidate.failure;
  }
  return incomplete(spelling, basename, [], lastFailure);
}

/** Build an identity for a dynamic executable without manufacturing a spelling. */
export function unresolvedExecutableIdentity(): ExecutableIdentity {
  return Object.freeze({ qualification: "unknown", reason: "unresolved-spelling" });
}

/** Exact, case-sensitive matching for the four supported executable selector forms. */
export function matchesExecutableSelector(
  identity: ExecutableIdentity,
  selector: Readonly<Record<string, unknown>>,
): boolean {
  const value = typeof selector.value === "string" ? selector.value : undefined;
  if (selector.kind === "executable") {
    const predicates: boolean[] = [];
    if (typeof selector.basename === "string") predicates.push(identity.qualification !== "unknown" && identity.basename === selector.basename);
    if (typeof selector.selectedPath === "string") predicates.push(identity.qualification === "known" && identity.selectedPath === selector.selectedPath);
    if (typeof selector.canonicalTarget === "string") predicates.push(identity.qualification === "known" && identity.canonicalTarget === selector.canonicalTarget);
    if (typeof selector.chainContains === "string") predicates.push(identity.qualification === "known" && identity.chain.includes(selector.chainContains));
    return predicates.length > 0 && predicates.every(Boolean);
  }
  if (selector.kind === "executable-basename") {
    return value !== undefined && identity.qualification !== "unknown" && identity.basename === value;
  }
  if (selector.kind === "executable-selected-path") {
    return value !== undefined && identity.qualification === "known" && identity.selectedPath === value;
  }
  if (selector.kind === "executable-canonical-target") {
    return value !== undefined && identity.qualification === "known" && identity.canonicalTarget === value;
  }
  if (selector.kind === "executable-chain-contains") {
    return value !== undefined && identity.qualification === "known" && identity.chain.includes(value);
  }
  return false;
}

function resolveDirect(spelling: string, basename: string, cwd: string, filesystem: ExecutableFilesystem): ExecutableIdentity {
  const selectedPath = absoluteFrom(cwd, spelling);
  const candidate = resolveCandidate(selectedPath, filesystem);
  if (candidate.kind === "known") return known(spelling, basename, selectedPath, candidate.canonicalTarget, candidate.chain);
  return incomplete(spelling, basename, candidate.chain, candidate.failure, selectedPath);
}

type CandidateResult =
  | { readonly kind: "known"; readonly canonicalTarget: string; readonly chain: readonly string[] }
  | { readonly kind: "incomplete"; readonly chain: readonly string[]; readonly failure: ExecutableIdentityFailure };

/**
 * Walk components in kernel order. In particular, a relative target replaces
 * the symlink component before subsequent `..` components are interpreted.
 */
function resolveCandidate(selectedPath: string, filesystem: ExecutableFilesystem): CandidateResult {
  let components = splitAbsolute(selectedPath);
  let resolved: string[] = [];
  const chain: string[] = [];
  const seenSymlinks = new Set<string>();
  let symlinkCount = 0;

  while (components.length > 0) {
    const component = components.shift()!;
    if (component === "." || component === "") continue;
    if (component === "..") {
      resolved.pop();
      continue;
    }
    const path = pathFromComponents([...resolved, component]);
    const lookup = lookupPath(filesystem, path);
    if (lookup.kind === "missing") return failure(chain, { kind: chain.length > 0 ? "broken-symlink" : "not-found", path });
    if (lookup.kind === "incomplete") return failure(chain, { kind: "filesystem", path, failure: lookup.failure });
    const isLast = components.length === 0;
    if (lookup.entry.kind === "symlink") {
      if (++symlinkCount > MAX_EXECUTABLE_SYMLINKS) return failure(chain, { kind: "symlink-depth", path });
      if (seenSymlinks.has(path)) return failure(chain, { kind: "symlink-loop", path });
      seenSymlinks.add(path);
      chain.push(path);
      components = [...splitPath(lookup.entry.target), ...components];
      if (lookup.entry.target.startsWith("/")) resolved = [];
      continue;
    }
    if (!isLast) {
      if (lookup.entry.kind !== "directory") return failure(chain, { kind: "not-found" });
      resolved.push(component);
      continue;
    }
    if (lookup.entry.kind === "directory") return failure(chain, { kind: "directory", path });
    if (!lookup.entry.executable) return failure(chain, { kind: "not-executable", path });
    return Object.freeze({ kind: "known", canonicalTarget: path, chain: Object.freeze([...chain, path]) });
  }
  return failure(chain, { kind: "not-found" });
}

function lookupPath(filesystem: ExecutableFilesystem, path: string): ExecutableFilesystemLookup {
  try {
    return filesystem.lstat(path);
  } catch {
    return Object.freeze({ kind: "incomplete", failure: "io" });
  }
}

function known(spelling: string, basename: string, selectedPath: string, canonicalTarget: string, chain: readonly string[]): ExecutableIdentity {
  return Object.freeze({ qualification: "known", spelling, basename, selectedPath, canonicalTarget, chain: Object.freeze([...chain]) });
}

function incomplete(
  spelling: string,
  basename: string,
  chain: readonly string[],
  failure: ExecutableIdentityFailure,
  selectedPath?: string,
): ExecutableIdentity {
  return Object.freeze({ qualification: "incomplete", spelling, basename, ...(selectedPath ? { selectedPath } : {}), chain: Object.freeze([...chain]), failure: Object.freeze(failure) });
}

function failure(chain: readonly string[], failure: ExecutableIdentityFailure): CandidateResult {
  return Object.freeze({ kind: "incomplete", chain: Object.freeze([...chain]), failure: Object.freeze(failure) });
}

function absoluteFrom(cwd: string, path: string): string {
  return path.startsWith("/") ? path : joinPath(cwd, path);
}

function joinPath(left: string, right: string): string {
  return `${left.replace(/\/+$/, "") || "/"}/${right.replace(/^\/+/, "")}`;
}

function splitAbsolute(path: string): string[] {
  return splitPath(path.startsWith("/") ? path.slice(1) : path);
}

function splitPath(path: string): string[] {
  return path.split("/");
}

function pathFromComponents(components: readonly string[]): string {
  return `/${components.join("/")}`;
}

function pathBasename(path: string): string {
  const parts = path.split("/");
  return parts[parts.length - 1] ?? path;
}
