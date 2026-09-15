import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  analyzeGhPrCreateCommand,
  initBashParser,
  type GhPrCreatePolicy,
} from "../src/index.ts";

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
  return analyzeGhPrCreateCommand(command, activePolicy).kind;
}

describe("gh pr create policy", () => {
  test("allows exact repository and organization targets regardless of flag placement", () => {
    expect(decision("gh pr create --repo github.com/acme/widgets --title fix --fill")).toBe("allow");
    expect(decision("gh --repo=github.com/acme/widgets pr create --fill")).toBe("allow");
    expect(decision("nice gh pr create -R github.com/trusted-org/any-repo --fill")).toBe("allow");
    expect(decision("gh pr --repo github.example.com/platform/service create --fill")).toBe("allow");
    expect(decision("gh pr new --repo github.com/acme/widgets --fill")).toBe("allow");
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
    expect(decision("gh alias import aliases.txt")).toBe("deny");
    expect(decision("gh create-pr --fill")).toBe("deny");
    expect(decision("gh extension exec create-pr --fill")).toBe("deny");
    expect(decision("gh ext exec create-pr --fill")).toBe("deny");
    expect(decision("gh extensions exec create-pr --fill")).toBe("deny");
    expect(decision("doas gh pr create --repo github.com/attacker/widgets --fill")).toBe("deny");
    expect(decision("gh pr new --repo github.com/attacker/widgets --fill")).toBe("deny");
    expect(decision("printf '%s\\n' 'gh pr create --repo github.com/attacker/widgets --fill' | bash")).toBe("deny");
    expect(decision("printf '%s\\n' 'g\\h pr create --repo github.com/attacker/widgets --fill' | bash")).toBe("deny");
    expect(decision("g\\" + "\n" + "h pr create --repo github.com/attacker/widgets --fill")).toBe("ignore");
    expect(decision("g\\" + "\n" + "h api user")).toBe("ignore");
    expect(decision("gh alias $'set' create-pr 'pr create --repo github.com/attacker/widgets'")).toBe("deny");
    expect(decision("gh ext $'exec' create-pr --fill")).toBe("deny");
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

  test("denies compound Bash calls instead of approving unrelated commands", () => {
    expect(decision("gh pr create --repo github.com/acme/widgets --fill; rm -rf generated")).toBe("deny");
    expect(decision("bash -c 'gh pr create --repo github.com/acme/widgets --fill'")).toBe("deny");
    expect(decision("g\\h pr create --repo github.com/attacker/widgets --fill")).toBe("deny");
  });

  test("allows assignment-resolved and transparently wrapped allowlisted invocations", () => {
    expect(decision("TOOL=gh; strace $TOOL pr create --repo github.com/acme/widgets --fill")).toBe("allow");
  });

  test("does not restrict documented non-PR gh commands", () => {
    expect(decision("gh discussion list")).toBe("ignore");
    expect(decision("gh agent-task list")).toBe("ignore");
    expect(decision("gh copilot --help")).toBe("ignore");
    expect(decision("gh skill list")).toBe("ignore");
    expect(decision("gh ext list")).toBe("ignore");
    expect(decision("gh environment")).toBe("ignore");
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

      expect(decision(command, generatedPolicy)).toBe(allowed ? "allow" : "deny");
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
        .toBe(allowed ? "allow" : "deny");
    }
  });
});
