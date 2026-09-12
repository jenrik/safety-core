import type { GhPrCreatePolicy } from "../../gh-pr-create.js";
import type { PolicyEvidence } from "../outcome.js";

export type GhPrCreateInvocationDecision =
  | { readonly kind: "allow"; readonly reason: string; readonly evidence: PolicyEvidence }
  | { readonly kind: "deny"; readonly reason: string; readonly evidence: PolicyEvidence };

export function analyzeGhPrCreateInvocation(
  repositories: readonly string[] | undefined,
  policy: GhPrCreatePolicy,
): GhPrCreateInvocationDecision {
  if (!repositories || repositories.length === 0) {
    return deny("Pull-request creation is blocked: provide an explicit --repo HOST/OWNER/REPO target that is allowlisted by the ghPrCreate profile");
  }
  for (const repository of repositories) {
    if (!hasExplicitHost(repository)) {
      return deny("Pull-request creation is blocked: use an explicit --repo HOST/OWNER/REPO target so the allowlist cannot be redirected by GH_HOST");
    }
    if (!isAllowedRepository(repository, policy)) {
      return deny(`Pull-request creation is blocked: repository ${repository} is not allowlisted by the ghPrCreate profile`);
    }
  }
  return allow("gh pr create auto-allowed for an allowlisted repository");
}

export function denyGhPrCreate(reason: string): GhPrCreateInvocationDecision {
  return deny(reason);
}

interface RepositoryIdentifier { readonly host: string; readonly owner: string; readonly name: string }
interface OrganizationIdentifier { readonly host: string; readonly owner: string }

function hasExplicitHost(repository: string): boolean {
  return repository.trim().split("/").length === 3;
}

function isAllowedRepository(repository: string, policy: GhPrCreatePolicy): boolean {
  const target = normalizeRepository(repository);
  if (!target) return false;
  return policy.allowedRepositories.some((candidate) => {
    const allowed = normalizeRepository(candidate);
    return allowed !== undefined && repositoriesEqual(target, allowed);
  }) || policy.allowedOrganizations.some((candidate) => {
    const allowed = normalizeOrganization(candidate);
    return allowed !== undefined && target.host === allowed.host && target.owner === allowed.owner;
  });
}

function normalizeRepository(value: string): RepositoryIdentifier | undefined {
  const parts = value.trim().toLowerCase().split("/");
  const [host, owner, name] = parts.length === 2 ? ["github.com", parts[0], parts[1]] : parts.length === 3 ? parts : [];
  return isIdentifier(host) && isIdentifier(owner) && isIdentifier(name) ? { host, owner, name } : undefined;
}

function normalizeOrganization(value: string): OrganizationIdentifier | undefined {
  const parts = value.trim().toLowerCase().split("/");
  const [host, owner] = parts.length === 1 ? ["github.com", parts[0]] : parts.length === 2 ? parts : [];
  return isIdentifier(host) && isIdentifier(owner) ? { host, owner } : undefined;
}

function repositoriesEqual(left: RepositoryIdentifier, right: RepositoryIdentifier): boolean {
  return left.host === right.host && left.owner === right.owner && left.name === right.name;
}

function isIdentifier(value: string | undefined): value is string {
  return value !== undefined && /^[a-z0-9][a-z0-9._-]*$/.test(value);
}

function evidence(decision: PolicyEvidence["decision"], reason: string): PolicyEvidence {
  return Object.freeze({ name: "gh-pr-create", decision, reason });
}

function allow(reason: string): GhPrCreateInvocationDecision {
  return Object.freeze({ kind: "allow", reason, evidence: evidence("allow", reason) });
}

function deny(reason: string): GhPrCreateInvocationDecision {
  return Object.freeze({ kind: "deny", reason, evidence: evidence("deny", reason) });
}
