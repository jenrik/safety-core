import { expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

test("Claude ghPrCreate hook denies when parser initialization fails", () => {
  const configHome = mkdtempSync(join(tmpdir(), "safety-core-gh-pr-hook-parser-"));
  try {
    mkdirSync(join(configHome, "safety-core"));
    writeFileSync(join(configHome, "safety-core", "profiles.json"), JSON.stringify({
      ghPrCreate: { enabled: true, allowedRepositories: ["acme/widgets"], allowedOrganizations: [] },
    }));
    const result = spawnSync(process.execPath, ["adapters/claude-code/gh_pr_create_policy.ts"], {
      cwd: process.cwd(),
      input: JSON.stringify({
        hook_event_name: "PreToolUse",
        tool_name: "Bash",
        tool_input: { command: "gh pr create --repo github.com/acme/widgets --fill" },
      }),
      encoding: "utf8",
      env: { ...process.env, SAFETY_CORE_CONFIG_HOME: configHome },
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('"permissionDecision":"deny"');
    expect(result.stdout).toContain("damaged safety-core hook deployment");
  } finally {
    rmSync(configHome, { force: true, recursive: true });
  }
});
