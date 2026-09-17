import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  STRICT_BASH_PROFILE_EXECUTABLES,
  evaluateConfiguredBash,
  initBashParser,
  type BashProfileSnapshot,
  type GhPrCreatePolicy,
} from "../src/index.ts";
import { ghNativeAliasesForRule } from "../src/bash/handlers/gh-command-line.ts";
import { GH_READ_ONLY_RULES } from "../src/bash/policies/gh-read-only.ts";

const policy: GhPrCreatePolicy = {
  enabled: true,
  allowedRepositories: ["acme/widgets", "github.example.com/platform/service"],
  allowedOrganizations: ["trusted-org"],
};

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-gh-pr-create-"));

beforeAll(async () => {
  // Keep the test runnable from both the source checkout and the Nix package.
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(
    existsSync(packagedWasm)
      ? packagedWasm
      : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"),
    join(wasmDir, "tree-sitter-bash.wasm"),
  );
  symlinkSync(
    join(process.cwd(), "node_modules", "web-tree-sitter"),
    join(wasmDir, "node_modules", "web-tree-sitter"),
  );
  await initBashParser(wasmDir);
});

afterAll(() => {
  rmSync(wasmDir, { force: true, recursive: true });
});

function decision(command: string, activePolicy: GhPrCreatePolicy = policy): string {
  const profileSnapshot: BashProfileSnapshot = Object.freeze({
    readOnlyBash: false,
    ghApiReadOnly: false,
    ghReadOnly: false,
    helmReadOnly: false,
    strictProfiles: Object.freeze(Object.fromEntries(STRICT_BASH_PROFILE_EXECUTABLES.map(([profile]) => [profile, false]))) as BashProfileSnapshot["strictProfiles"],
    ghPrCreate: Object.freeze(activePolicy),
    limits: Object.freeze({ maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 7_500, maxWorkItems: 10_000 }),
  });
  return evaluateConfiguredBash({ source: command, initialEnvironment: { kind: "verified", values: { GH_PROMPT_DISABLED: "1" } }, profileSnapshot }).permission.kind;
}

describe("gh pr create policy", () => {
  test("keeps allowlisted repository and organization targets prompt-gated", () => {
    expect(decision("gh pr create --repo github.com/acme/widgets --title fix --fill")).toBe("defer");
    expect(decision("gh --repo=github.com/acme/widgets pr create --fill")).toBe("defer");
    expect(decision("nice gh pr create -R github.com/trusted-org/any-repo --fill")).toBe("defer");
    expect(decision("gh pr --repo github.example.com/platform/service create --fill")).toBe("defer");
    expect(decision("gh pr new --repo github.com/acme/widgets --fill")).toBe("defer");
    expect(decision("gh pr create --repo github.com/acme/widgets --title fix --body details")).toBe("defer");
  });

  test("denies unscoped, malformed, and non-allowlisted targets", () => {
    expect(decision("gh pr create --fill")).toBe("deny");
    expect(decision("gh pr create --repo")).toBe("deny");
    expect(decision("GH_HOST=attacker.example gh pr create --repo acme/widgets --fill")).toBe("deny");
    expect(decision("gh pr create --repo attacker/widgets --fill")).toBe("deny");
    expect(decision("gh pr create --repo github.example.com/acme/widgets --fill")).toBe("deny");
    expect(decision("env /usr/bin/gh pr create --repo github.com/attacker/widgets --fill")).toBe("deny");
    expect(decision("g''h pr create --repo github.com/attacker/widgets --fill")).toBe("deny");
    expect(decision("G=gh; $G pr create --repo github.com/attacker/widgets --fill")).toBe("deny");
  });

  test("denies interactive, external-program, local-input, and malformed creation forms", () => {
    for (const command of [
      "GH_EDITOR=printf gh pr create --repo github.com/acme/widgets --editor",
      "GH_BROWSER=printf gh pr create --repo github.com/acme/widgets --web",
      "gh pr create --repo github.com/acme/widgets --body-file README.md --title test",
      "gh pr create --repo github.com/acme/widgets --template pull_request.md --title test",
      "gh pr create --repo github.com/acme/widgets --recover recovery.txt",
      "gh pr create --repo github.com/acme/widgets --attach screenshot.png --fill",
      "gh pr create --repo github.com/acme/widgets --dry-run --fill",
      "gh pr create --repo github.com/acme/widgets --unknown --fill",
      "gh pr create --repo github.com/acme/widgets --fill --fill-first",
      "gh pr create --repo github.com/acme/widgets --title fix",
      "gh pr create --repo github.com/acme/widgets --body details",
      "gh pr create --repo github.com/acme/widgets --fill extra",
      "gh pr create --repo github.com/acme/widgets --repo github.com/acme/widgets --fill",
      "GH_EDITOR=printf gh pr create --repo github.com/acme/widgets --fill",
      "/usr/bin/gh pr create --repo github.com/acme/widgets --fill",
      "gh pr create --repo github.com/acme/widgets --fill > result.txt",
    ]) expect(decision(command), command).toBe("deny");
  });

  test("denies direct gh api calls, including pull-request equivalents", () => {
    expect(decision("gh api -X POST repos/acme/widgets/pulls -f title=fix")).toBe("deny");
    expect(decision("gh api repos/attacker/widgets/pulls --method=POST -f title=fix")).toBe("deny");
    expect(decision("gh api graphql -f 'query=mutation { createPullRequest(input: {}) { pullRequest { id } } }'")).toBe("deny");
    expect(decision("gh api graphql --input pull-request-mutation.json")).toBe("deny");
    expect(decision("gh api graphql -f 'query=query { viewer { login } }'")).toBe("deny");
    expect(decision("GH_REPO=attacker/widgets gh api -X POST 'repos/{owner}/{repo}/pulls' -f title=fix")).toBe("deny");
    expect(decision("endpoint='repos/attacker/widgets/pulls'; gh api -X POST \"$endpoint\" -f title=fix")).toBe("deny");
    expect(decision("gh api -X POST https://api.github.com/repos/attacker/widgets/pulls -f title=fix")).toBe("deny");
    expect(decision("gh api -X POST https://github.example/api/v3/repos/attacker/widgets/pulls -f title=fix")).toBe("deny");
    expect(decision("gh api https://api.github.com/graphql -f 'query=mutation { createPullRequest(input: {}) { pullRequest { id } } }'")).toBe("deny");
    expect(decision("gh api repos/attacker/widgets/'pulls' -f title=fix")).toBe("deny");
    expect(decision("gh api graphql -f 'query=mutation { create'Pull'Request(input: {}) { pullRequest { id } } }'")).toBe("deny");
  });

  test("ignores non-creation gh commands and disabled profiles", () => {
    expect(decision("gh pr list --repo attacker/widgets")).toBe("ignore");
    expect(decision("gh issue create --repo github.com/acme/widgets --title pr --body create")).toBe("ignore");
    expect(decision("gh api repos/acme/widgets/pulls")).toBe("deny");
    expect(decision("gh pr create --repo github.com/attacker/widgets", { ...policy, enabled: false })).toBe("ignore");
  });

  test("denies nested, aliased, and extension-based bypasses", () => {
    expect(decision("printf '%s' \"$(gh pr create --repo github.com/attacker/widgets --fill)\"")).toBe("deny");
    expect(decision("bash -c 'gh pr create --repo github.com/attacker/widgets --fill'")).toBe("deny");
    expect(decision("eval 'gh pr create --repo github.com/attacker/widgets --fill'")).toBe("deny");
    expect(decision("gh alias set create-pr 'pr create --repo github.com/attacker/widgets'")).toBe("deny");
    expect(decision("gh alias set 'api create-pr' 'api repos/attacker/widgets/pulls -f title=fix'")).toBe("deny");
    expect(decision("gh pr create-pr --fill")).toBe("deny");
    expect(decision("gh repo custom-command")).toBe("deny");
    expect(decision("gh rs custom-command")).toBe("deny");
    expect(decision("gh alias import aliases.txt")).toBe("deny");
    expect(decision("gh create-pr --fill")).toBe("deny");
    expect(decision("gh extension exec create-pr --fill")).toBe("deny");
    expect(decision("gh ext exec create-pr --fill")).toBe("deny");
    expect(decision("gh extensions exec create-pr --fill")).toBe("deny");
    expect(decision("doas gh pr create --repo github.com/attacker/widgets --fill")).toBe("deny");
    expect(decision("strace --output=trace.log gh pr create --repo github.com/attacker/widgets --fill")).toBe("deny");
    expect(decision("timeout --verbose 5s gh pr create --repo github.com/attacker/widgets --fill")).toBe("deny");
    expect(decision("env --argv0=gh gh pr create --repo github.com/attacker/widgets --fill")).toBe("deny");
    expect(decision("gh pr new --repo github.com/attacker/widgets --fill")).toBe("deny");
    expect(decision("printf '%s\\n' 'gh pr create --repo github.com/attacker/widgets --fill' | bash")).toBe("deny");
    expect(decision("printf '%s\\n' 'g\\h pr create --repo github.com/attacker/widgets --fill' | bash")).toBe("deny");
    expect(decision("g\\" + "\n" + "h pr create --repo github.com/attacker/widgets --fill")).toBe("ignore");
    expect(decision("g\\" + "\n" + "h api user")).toBe("ignore");
    expect(decision("gh alias $'set' create-pr 'pr create --repo github.com/attacker/widgets'")).toBe("deny");
    expect(decision("gh ext $'exec' create-pr --fill")).toBe("deny");
  });

  test("property: unknown children under every native command-group form are denied", () => {
    for (const rule of GH_READ_ONLY_RULES.filter((candidate) => candidate.kind === "group")) {
      const forms = [rule.path, ...ghNativeAliasesForRule(rule)];
      for (const form of forms) {
        const command = `gh ${form.join(" ")} safety-core-dynamic-child`;
        expect(decision(command), command).toBe("deny");
      }
    }
  });

  test("property: unresolved children under every native command-group form are denied", () => {
    for (const rule of GH_READ_ONLY_RULES.filter((candidate) => candidate.kind === "group")) {
      const forms = [rule.path, ...ghNativeAliasesForRule(rule)];
      for (const form of forms) {
        const command = `CHILD=$(printf safety-core-dynamic-child); gh ${form.join(" ")} "$CHILD"`;
        expect(decision(command), command).toBe("deny");
      }
    }
  });

  test("denies pipeline-fed interpreters through every transparent wrapper", () => {
    const wrappers = [
      "env bash",
      "command bash",
      "doas bash",
      "exec bash",
      "nice bash",
      "nohup bash",
      "setsid bash",
      "stdbuf -oL bash",
      "timeout 5s bash",
      "strace bash",
    ];
    for (const interpreter of wrappers) {
      expect(decision(`printf '%s\\n' 'gh pr create --repo github.com/attacker/widgets --fill' | ${interpreter}`), interpreter)
        .toBe("deny");
    }
  });

  test("defers compound Bash calls instead of approving unrelated commands", () => {
    expect(decision("gh pr create --repo github.com/acme/widgets --fill; rm -rf generated")).toBe("defer");
    expect(decision("bash -c 'gh pr create --repo github.com/acme/widgets --fill'")).toBe("deny");
    expect(decision("g\\h pr create --repo github.com/attacker/widgets --fill")).toBe("deny");
  });

  test("keeps assignment-resolved and wrapped allowlisted invocations prompt-gated", () => {
    expect(decision("TOOL=gh; strace $TOOL pr create --repo github.com/acme/widgets --fill")).toBe("defer");
  });

  test("does not restrict documented non-PR gh commands", () => {
    expect(decision("gh discussion list")).toBe("ignore");
    expect(decision("gh agent-task list")).toBe("ignore");
    expect(decision("gh copilot --help")).toBe("ignore");
    expect(decision("gh skill list")).toBe("ignore");
    expect(decision("gh ext list")).toBe("ignore");
    expect(decision("gh environment")).toBe("ignore");
    expect(decision("gh pr ls")).toBe("ignore");
    expect(decision("gh credits")).toBe("ignore");
    expect(decision("gh send-telemetry --help")).toBe("ignore");
  });

  test("property: repository and organization allowlists never admit a different owner or repo", () => {
    let state = 0x8badf00d;
    const random = (): number => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state;
    };

    for (let index = 0; index < 500; index++) {
      const owner = `owner${random() % 100000}`;
      const repository = `repo${random() % 100000}`;
      const allowed = random() % 2 === 0;
      const target = allowed
        ? `github.com/${owner}/${repository}`
        : `github.com/${owner}${random() % 9 + 1}/${repository}`;
      const flag = ["--repo", "-R", "--repo=", "-R="][random() % 4];
      const value = flag.endsWith("=") ? `${flag}${target}` : `${flag} ${target}`;
      const command = random() % 2 === 0
        ? `gh pr create --fill ${value}`
        : `gh ${value} pr create --fill`;
      const generatedPolicy: GhPrCreatePolicy = {
        enabled: true,
        allowedRepositories: [`${owner}/${repository}`],
        allowedOrganizations: [],
      };

      expect(decision(command, generatedPolicy)).toBe(allowed ? "defer" : "deny");
    }
  });

  test("property: organization allowlists admit every repository for that organization only", () => {
    let state = 0x12345678;
    const random = (): number => {
      state = (Math.imul(state, 1103515245) + 12345) >>> 0;
      return state;
    };

    for (let index = 0; index < 500; index++) {
      const organization = `organization${random() % 100000}`;
      const repository = `repo${random() % 100000}`;
      const allowed = random() % 2 === 0;
      const targetOrganization = allowed ? organization : `${organization}${random() % 9 + 1}`;
      const generatedPolicy: GhPrCreatePolicy = {
        enabled: true,
        allowedRepositories: [],
        allowedOrganizations: [organization],
      };

      expect(decision(`gh pr create --repo github.com/${targetOrganization}/${repository} --fill`, generatedPolicy))
        .toBe(allowed ? "defer" : "deny");
    }
  });
});
