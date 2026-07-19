// kubectl-specific policy: auto-allow read-only subcommands, deny known
// value-exposing ones, defer everything else to the harness' default gate.

import {
  KUBECTL_ALWAYS_ALLOW,
  KUBECTL_AUTH_ALLOW,
  KUBECTL_FLAGS_WITH_VALUES,
  KUBECTL_ROLLOUT_ALLOW,
  KUBECTL_SECRET_TYPES,
} from "./patterns.js";
import { splitShellSegments, stripQuotes, tokenize } from "./shell.js";

export type KubectlDecision =
  | { kind: "allow"; reason: string }
  | { kind: "deny"; reason: string }
  | { kind: "defer" }
  | { kind: "ignore" }; // not a kubectl command at all

/** Analyse a shell command for kubectl policy. Returns:
 *   - allow  → hook should override permission gate to allow
 *   - deny   → hook should override permission gate to deny
 *   - defer  → hook should stay silent; let harness default rules decide
 *   - ignore → command is not kubectl
 */
export function analyzeKubectl(command: string): KubectlDecision {
  const tokens = tokenize(command).map(stripQuotes);
  const kubectlIdx = findKubectl(tokens);
  if (kubectlIdx < 0) return { kind: "ignore" };

  const sub = nextPositional(tokens, kubectlIdx + 1);
  if (sub.value === undefined) return { kind: "ignore" };

  if (sub.value === "view-secret") {
    return {
      kind: "deny",
      reason:
        "kubectl view-secret is blocked: it decodes and displays Secret values in plaintext.",
    };
  }

  if (KUBECTL_ALWAYS_ALLOW.has(sub.value)) {
    return { kind: "allow", reason: `kubectl ${sub.value} auto-allowed (read-only)` };
  }

  if (sub.value === "get") {
    const resource = nextPositional(tokens, sub.next).value;
    if (resource === undefined) return { kind: "defer" };
    const types = new Set(
      resource.split(",").map((r) => r.split("/")[0].toLowerCase()),
    );
    for (const t of types) {
      if (KUBECTL_SECRET_TYPES.has(t)) {
        // Defer to the harness LLM judge / permission gate. get on Secret
        // resources can either be metadata-only (safe) or full YAML dumps
        // (unsafe); the judge decides.
        return { kind: "defer" };
      }
    }
    return { kind: "allow", reason: "kubectl get auto-allowed" };
  }

  if (sub.value === "rollout") {
    const sub2 = nextPositional(tokens, sub.next).value;
    if (sub2 && KUBECTL_ROLLOUT_ALLOW.has(sub2)) {
      return { kind: "allow", reason: `kubectl rollout ${sub2} auto-allowed (read-only)` };
    }
    return { kind: "defer" };
  }

  if (sub.value === "config") {
    const sub2 = nextPositional(tokens, sub.next).value;
    if (sub2 === "get-contexts") {
      return {
        kind: "allow",
        reason: "kubectl config get-contexts auto-allowed (read-only, no credentials)",
      };
    }
    return { kind: "defer" };
  }

  if (sub.value === "auth") {
    const sub2 = nextPositional(tokens, sub.next).value;
    if (sub2 && KUBECTL_AUTH_ALLOW.has(sub2)) {
      return { kind: "allow", reason: `kubectl auth ${sub2} auto-allowed (read-only)` };
    }
    return { kind: "defer" };
  }

  if (sub.value === "plugin") {
    const sub2 = nextPositional(tokens, sub.next).value;
    if (sub2 === "list") {
      return { kind: "allow", reason: "kubectl plugin list auto-allowed (read-only)" };
    }
    return { kind: "defer" };
  }

  return { kind: "defer" };
}

// ─── Bash-level scan variant used by opencode/pi (as fallback deny) ──────────

/** Return a reason string if `command` invokes kubectl on Secrets, else null.
 *  Used by harnesses that only have a hard-block hook and no permission gate. */
export function checkBashForKubectlSecret(command: string): string | null {
  for (const segment of splitShellSegments(command)) {
    const decision = analyzeKubectl(segment);
    if (decision.kind === "deny") return decision.reason;
    if (decision.kind === "defer") {
      // In pi/opencode we don't have a separate "defer to LLM judge" mode:
      // for kubectl get on Secrets, block outright.
      const tokens = tokenize(segment).map(stripQuotes);
      const idx = findKubectl(tokens);
      if (idx < 0) continue;
      const sub = nextPositional(tokens, idx + 1);
      if (sub.value !== "get") continue;
      const resource = nextPositional(tokens, sub.next).value;
      if (!resource) continue;
      const types = resource.split(",").map((r) => r.split("/")[0].toLowerCase());
      if (types.some((t) => KUBECTL_SECRET_TYPES.has(t))) {
        return "kubectl get Secret is not auto-approved. Use metadata-only output or request confirmation for a safe command.";
      }
    }
  }
  return null;
}

// ─── Audit summary ──────────────────────────────────────────────────────────

export interface KubectlAuditRecord {
  kubectl_subcommand: string | null;
  resource: string | null;
  command_length: number;
}

/** Return an audit summary of a kubectl command that touched a Secret, or
 *  null if the command doesn't reference kubectl / Secrets. Never returns the
 *  raw command text — value-bearing --from-literal arguments must not persist. */
export function summariseKubectlSecret(command: string): KubectlAuditRecord | null {
  const tokens = tokenize(command).map(stripQuotes);
  const idx = findKubectl(tokens);
  if (idx < 0) return null;

  const mentionsSecret = tokens.some((t) =>
    /(^|[/,])secrets?(?:$|[/,])|view-secret/.test(t),
  );
  if (!mentionsSecret) return null;

  const sub = nextPositional(tokens, idx + 1);
  const resource = sub.value !== undefined ? nextPositional(tokens, sub.next).value : undefined;

  return {
    kubectl_subcommand: sub.value ?? null,
    resource: resource ? resource.split("/")[0].split("=")[0] : null,
    command_length: command.length,
  };
}

// ─── Token helpers ──────────────────────────────────────────────────────────

function findKubectl(tokens: string[]): number {
  return tokens.findIndex((t) => t === "kubectl" || t.endsWith("/kubectl"));
}

interface PositionalResult { value: string | undefined; next: number }

function nextPositional(tokens: string[], start: number): PositionalResult {
  let i = start;
  while (i < tokens.length) {
    const t = tokens[i];
    if (!t.startsWith("-")) return { value: t, next: i + 1 };
    if (t.includes("=")) {
      i++;
    } else if (KUBECTL_FLAGS_WITH_VALUES.has(t)) {
      i += 2;
    } else {
      i++;
    }
  }
  return { value: undefined, next: tokens.length };
}
