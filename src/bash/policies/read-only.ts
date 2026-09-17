import { SECRET_EXCEPTIONS, SECRET_PATTERNS } from "../../patterns.js";
import { basename, matchesAnyGlob } from "../../shell.js";
import type { PolicyEvidence } from "../outcome.js";

export interface AllowedFlag { readonly long?: string; readonly short?: string; readonly takesValue: boolean }
export type ReadOnlyPolicyName = "generic-read-only" | "gh-read-only" | "helm-read-only" | "strict-read-only";
export type ReadOnlyInvocationDecision =
  | { readonly kind: "allow"; readonly reason: string; readonly evidence: PolicyEvidence }
  | { readonly kind: "defer"; readonly evidence: PolicyEvidence };

export const HELM_CREDENTIAL_SAFE_COMMANDS = new Set(["completion", "inspect:chart", "search:hub", "search:repo", "show:chart", "verify", "version"]);
export const STRICT_READ_ONLY_COMMANDS: Readonly<Record<string, ReadonlySet<string>>> = {
  argocd: new Set(["account:can-i", "account:get", "account:get-user-info", "account:list", "app:list", "appset:list", "cluster:list", "proj:list", "proj:role:list", "project:list", "project:role:list", "repo:list", "version"]),
  cosign: new Set(["tree", "verify", "verify-attestation", "verify-blob", "verify-blob-attestation", "version"]), crane: new Set(["catalog", "digest", "ls", "manifest", "validate", "version"]),
  docker: new Set(["config:list", "config:ls", "context:list", "context:ls", "image:list", "image:ls", "images", "info", "network:list", "network:ls", "node:list", "node:ls", "plugin:list", "plugin:ls", "search", "secret:list", "secret:ls", "service:list", "service:ls", "stack:list", "stack:ls", "system:df", "version", "volume:list", "volume:ls"]),
  jf: new Set(["config:show", "options", "rt:search", "stats:rt", "version"]), jfrog: new Set(["config:show", "options", "rt:search", "stats:rt", "version"]),
  kubectl: new Set(["api-resources", "api-versions", "auth:can-i", "auth:whoami", "cluster-info", "config:current-context", "config:get-contexts", "explain", "get", "plugin:list", "version"]),
  nix: new Set(["hash:file", "hash:path", "hash:to-base16", "hash:to-base32", "hash:to-base64", "help-stores", "nar:ls", "path-info", "store:ping", "store:verify", "version", "why-depends"]), "nix-env": new Set(["version"]), "nix-store": new Set(["version"]),
  oc: new Set(["api-resources", "api-versions", "auth:can-i", "cluster-info", "config:current-context", "config:get-contexts", "explain", "get", "plugin:list", "projects", "version", "whoami"]),
  podman: new Set(["artifact:list", "artifact:ls", "diff", "image:list", "image:ls", "images", "info", "network:list", "network:ls", "pod:list", "pod:ls", "pod:ps", "port", "search", "secret:list", "secret:ls", "system:connection:ls", "system:connection:list", "system:df", "version", "volume:list", "volume:ls"]), "podman-compose": new Set(["images", "port", "version"]), skopeo: new Set(["list-tags", "manifest-digest", "standalone-verify", "version"]), tofu: new Set(["version"]), npm: new Set(["explain", "find", "help-search", "la", "list", "ll", "ls", "outdated", "prefix", "root", "s", "se", "search", "why"]), pip: new Set(["check", "freeze", "inspect", "list", "show", "version"]), uv: new Set(["cache:dir", "cache:size", "check", "help", "pip:check", "pip:freeze", "pip:list", "pip:show", "pip:tree", "python:dir", "python:find", "python:list", "self:version", "tool:dir", "tool:list", "version", "workspace:dir", "workspace:list", "workspace:metadata"]), yarn: new Set(["explain", "explain:peer-requirements", "info", "npm:info", "npm:tag:list", "plugin:list", "plugin:runtime", "why", "workspaces:list"]),
};
export const STRICT_ALLOWED_FLAGS: Readonly<Record<string, readonly AllowedFlag[]>> = {
  // The user explicitly treats every non-protected kubectl/oc resource as safe
  // to read, regardless of its selected rendering format.
  kubectl: [
    { long: "--namespace", short: "-n", takesValue: true }, { long: "--context", takesValue: true },
    { long: "--output", short: "-o", takesValue: true },
  ],
  oc: [
    { long: "--namespace", short: "-n", takesValue: true }, { long: "--context", takesValue: true },
    { long: "--output", short: "-o", takesValue: true },
  ],
  npm: [{ long: "--json", takesValue: false }],
};

export function isSecretPath(value: string): boolean {
  const name = basename(value);
  return !!name && !matchesAnyGlob(name, SECRET_EXCEPTIONS) && matchesAnyGlob(name, SECRET_PATTERNS);
}

export function readOnlyAllow(name: ReadOnlyPolicyName, tool: string): ReadOnlyInvocationDecision {
  const reason = `${tool} auto-allowed by the read-only profile`;
  return Object.freeze({ kind: "allow", reason, evidence: Object.freeze({ name, decision: "allow", reason, readOnly: Object.freeze({ tool }) }) });
}

export function readOnlyDefer(name: ReadOnlyPolicyName, tool: string): ReadOnlyInvocationDecision {
  return Object.freeze({ kind: "defer", evidence: Object.freeze({ name, decision: "defer", readOnly: Object.freeze({ tool }) }) });
}
