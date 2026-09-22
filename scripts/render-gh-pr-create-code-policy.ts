export interface GhPrCreateCodePolicyOptions {
  readonly allowedRepositories: readonly string[];
  readonly allowedOrganizations: readonly string[];
}

/** Render a complete, bundle-ready policy with its allowlist fixed in source. */
export function renderGhPrCreateCodePolicy(options: GhPrCreateCodePolicyOptions): string {
  const allowedRepositories = validateList(options.allowedRepositories, "allowedRepositories", 2, 3);
  const allowedOrganizations = validateList(options.allowedOrganizations, "allowedOrganizations", 1, 2);
  return [
    'import { createGhPrCreatePolicy } from "./policies/code/gh-pr-create.policy.js";',
    "",
    `const allowedRepositories = Object.freeze(${JSON.stringify(allowedRepositories)});`,
    `const allowedOrganizations = Object.freeze(${JSON.stringify(allowedOrganizations)});`,
    "",
    "export default createGhPrCreatePolicy({ allowedRepositories, allowedOrganizations });",
    "",
  ].join("\n");
}

function validateList(value: readonly string[], name: string, minimumSegments: number, maximumSegments: number): readonly string[] {
  if (!Array.isArray(value)) throw new TypeError(`${name} must be an array of repository identifiers`);
  const normalized = value.map((item, index) => {
    if (typeof item !== "string") throw new TypeError(`${name}[${index}] must be a string`);
    const parts = item.trim().toLowerCase().split("/");
    if (parts.length < minimumSegments || parts.length > maximumSegments || !parts.every(isIdentifier)) {
      throw new TypeError(`${name}[${index}] must be a slash-separated GitHub identifier`);
    }
    return parts.join("/");
  });
  if (new Set(normalized).size !== normalized.length) throw new TypeError(`${name} must not contain duplicate identifiers`);
  return Object.freeze(normalized);
}

function isIdentifier(value: string): boolean {
  return /^[a-z0-9][a-z0-9._-]*$/.test(value);
}
