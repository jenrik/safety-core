import { isBindingResolvedWord, type NormalizedCommand } from "../expand.js";
import { SECRET_EXCEPTIONS, SECRET_PATTERNS } from "../../patterns.js";
import { basename, matchesAnyGlob } from "../../shell.js";

export type SecretReadPolicyDecision =
  | { readonly kind: "allow"; readonly evidence: { readonly name: "secret-read"; readonly decision: "allow" } }
  | { readonly kind: "deny"; readonly evidence: { readonly name: "secret-read"; readonly decision: "deny"; readonly reason: string } };

export function analyzeSecretReadInvocation(invocation: NormalizedCommand): SecretReadPolicyDecision {
  const redirect = analyzeSecretRedirectInvocation(invocation);
  if (redirect.kind === "deny") return redirect;
  for (const argument of invocation.argv) {
    if (argument.kind !== "known" || argument.value.startsWith("-")) continue;
    if (isSecretPath(argument.value)) return deny(isBindingResolvedWord(argument)
      ? `bash \`${executableName(invocation)}\` on a protected secret file`
      : `bash \`${executableName(invocation)}\` on '${basename(argument.value)}'`);
  }
  return Object.freeze({ kind: "allow", evidence: Object.freeze({ name: "secret-read", decision: "allow" }) });
}

/** Apply secret input-redirection protection before executable-specific policy. */
export function analyzeSecretRedirectInvocation(invocation: NormalizedCommand): SecretReadPolicyDecision {
  for (const redirect of invocation.redirects) {
    if (redirect.kind !== "input" || redirect.target?.kind !== "known") continue;
    if (isSecretPath(redirect.target.value)) return deny(isBindingResolvedWord(redirect.target)
      ? "bash redirect from a protected secret file"
      : `bash redirect from '${basename(redirect.target.value)}'`);
  }
  return Object.freeze({ kind: "allow", evidence: Object.freeze({ name: "secret-read", decision: "allow" }) });
}

function deny(reason: string): SecretReadPolicyDecision {
  return Object.freeze({ kind: "deny", evidence: Object.freeze({ name: "secret-read", decision: "deny", reason }) });
}

function executableName(invocation: NormalizedCommand): string {
  return invocation.executable?.kind === "known" ? invocation.executable.value : "reader";
}

function isSecretPath(path: string): boolean {
  const name = basename(path);
  return Boolean(name) && !matchesAnyGlob(name, SECRET_EXCEPTIONS) && matchesAnyGlob(name, SECRET_PATTERNS);
}
