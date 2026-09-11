// kubectl-specific policy: auto-allow read-only subcommands, deny known
// value-exposing ones, defer everything else to the harness' default gate.

import {
  KUBECTL_ALWAYS_ALLOW,
  KUBECTL_AUTH_ALLOW,
  KUBECTL_FLAGS_WITH_VALUES,
  KUBECTL_ROLLOUT_ALLOW,
  KUBECTL_PROTECTED_TYPES,
} from "./patterns.js";
import { basename, parseBash, type SimpleCommand } from "./shell.js";

export type KubectlDecision =
  | { kind: "allow"; reason: string }
  | { kind: "deny"; reason: string }
  | { kind: "defer" }
  | { kind: "ignore" }; // not a kubectl command at all

/**
 * Analyse a shell command for kubectl policy. Returns:
 *   - allow  → hook should override permission gate to allow
 *   - deny   → hook should override permission gate to deny
 *   - defer  → hook should stay silent; let harness default rules decide
 *   - ignore → command is not kubectl
 */
export function analyzeKubectl(command: string): KubectlDecision {
  const commands = parseBash(command);
  const kubectl = commands.find(isKubectl);
  if (!kubectl) return { kind: "ignore" };

  const sub = kubectl.args[0];
  if (!sub) return { kind: "ignore" };

  if (sub === "view-secret") {
    return {
      kind: "deny",
      reason:
        "kubectl view-secret is blocked: it decodes and displays Secret values in plaintext.",
    };
  }

  if (KUBECTL_ALWAYS_ALLOW.has(sub)) {
    return { kind: "allow", reason: `kubectl ${sub} auto-allowed (read-only)` };
  }

  if (sub === "get") {
    const resources = positionalArgs(kubectl.args, 1);
    if (resources.length === 0) return { kind: "defer" };
    if (kubectlResourceOperandsRequireReview(resources)) {
      // Defer to the harness LLM judge / permission gate. get on Secret
      // resources can either be metadata-only (safe) or full YAML dumps
      // (unsafe); the judge decides.
      return { kind: "defer" };
    }
    return { kind: "allow", reason: "kubectl get auto-allowed" };
  }

  if (sub === "rollout") {
    const sub2 = kubectl.args[1];
    if (sub2 && KUBECTL_ROLLOUT_ALLOW.has(sub2)) {
      return { kind: "allow", reason: `kubectl rollout ${sub2} auto-allowed (read-only)` };
    }
    return { kind: "defer" };
  }

  if (sub === "config") {
    const sub2 = kubectl.args[1];
    if (sub2 === "get-contexts") {
      return {
        kind: "allow",
        reason: "kubectl config get-contexts auto-allowed (read-only, no credentials)",
      };
    }
    return { kind: "defer" };
  }

  if (sub === "auth") {
    const sub2 = kubectl.args[1];
    if (sub2 && KUBECTL_AUTH_ALLOW.has(sub2)) {
      return { kind: "allow", reason: `kubectl auth ${sub2} auto-allowed (read-only)` };
    }
    return { kind: "defer" };
  }

  if (sub === "plugin") {
    const sub2 = kubectl.args[1];
    if (sub2 === "list") {
      return { kind: "allow", reason: "kubectl plugin list auto-allowed (read-only)" };
    }
    return { kind: "defer" };
  }

  return { kind: "defer" };
}

// ─── Bash-level scan variant used by opencode/pi (as fallback deny) ──────────

/**
 * Return a reason string if `command` invokes kubectl on Secrets, else null.
 * Used by harnesses that only have a hard-block hook and no permission gate.
 */
export function checkBashForKubectlSecret(command: string): string | null {
  const commands = parseBash(command);
  const kubectl = commands.find(isKubectl);
  if (!kubectl) return null;

  const decision = analyzeKubectl(command);
  if (decision.kind === "deny") return decision.reason;
  if (decision.kind !== "defer") return null;

  // In pi/opencode we don't have a separate "defer to LLM judge" mode:
  // for kubectl get on Secrets, block outright.
  const sub = kubectl.args[0];
  if (sub !== "get") return null;

  const resources = positionalArgs(kubectl.args, 1);
  if (resources.length === 0) return null;

  if (kubectlResourceOperandsRequireReview(resources)) {
    return "kubectl get Secret is not auto-approved. Use metadata-only output or request confirmation for a safe command.";
  }

  return null;
}

// ─── Audit summary ──────────────────────────────────────────────────────────

export interface KubectlAuditRecord {
  kubectl_subcommand: string | null;
  resource: string | null;
  command_length: number;
}

/**
 * Return an audit summary of a kubectl command that touched a Secret, or
 * null if the command doesn't reference kubectl / Secrets. Never returns the
 * raw command text — value-bearing --from-literal arguments must not persist.
 */
export function summariseKubectlSecret(command: string): KubectlAuditRecord | null {
  const commands = parseBash(command);
  const kubectl = commands.find(isKubectl);
  if (!kubectl) return null;

  // Check if the command mentions a Secret resource anywhere in its args.
  const mentionsSecret = kubectl.args.some(
    (a) => /(^|[/,])secrets?(?:$|[/,])|view-secret/.test(a),
  );
  if (!mentionsSecret) return null;

  const sub = kubectl.args[0] ?? null;
  const resource = kubectl.args.length > 1 ? kubectl.args[1].split("/")[0].split("=")[0] : null;

  return {
    kubectl_subcommand: sub,
    resource,
    command_length: command.length,
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function isKubectl(cmd: SimpleCommand): boolean {
  return cmd.name === "kubectl";
}

/** Normalize TYPE[.VERSION[.GROUP]][/NAME] to its resource type. */
export function kubectlResourceType(resource: string): string {
  return resource.split("/", 1)[0].split(".", 1)[0].toLowerCase();
}

/** True for Kubernetes resource types whose metadata can lead to credentials. */
export function isProtectedKubectlResource(resource: string): boolean {
  return KUBECTL_PROTECTED_TYPES.has(kubectlResourceType(resource));
}

/**
 * Check whether `kubectl get` operands need review. A bare first type may be
 * followed by names; mixed bare-type and TYPE/NAME forms are ambiguous.
 */
export function kubectlResourceOperandsRequireReview(operands: readonly string[]): boolean {
  const [first, ...remaining] = operands;
  if (!first) return false;
  if (!first.includes("/") && remaining.some((operand) => operand.includes("/"))) return true;
  const resources = first.includes("/") ? operands : [first];
  return resources.some((resource) => resource.split(",").some(isProtectedKubectlResource));
}

/** Return positional arguments at or after `start`, skipping flags and values. */
function positionalArgs(args: readonly string[], start: number): string[] {
  const positionals: string[] = [];
  let i = start;
  while (i < args.length) {
    const t = args[i];
    if (!t.startsWith("-")) {
      positionals.push(t);
      i++;
    } else if (!t.includes("=") && KUBECTL_FLAGS_WITH_VALUES.has(t)) {
      i += 2;
    } else {
      i++;
    }
  }
  return positionals;
}
