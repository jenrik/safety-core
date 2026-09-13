import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { replayHistoricalBashEvent, replayHistoricalBashEvents } from "../analysis/opencode-history-adapter.ts";
import { isBashParserInitialized, setJudgeProvider } from "../src/index.ts";

const configHome = mkdtempSync(join(tmpdir(), "safety-core-opencode-history-profile-"));
const originalConfigHome = process.env.SAFETY_CORE_CONFIG_HOME;

beforeAll(async () => {
  process.env.SAFETY_CORE_CONFIG_HOME = configHome;
  mkdirSync(join(configHome, "safety-core"), { recursive: true });
});

afterAll(() => {
  if (originalConfigHome === undefined) delete process.env.SAFETY_CORE_CONFIG_HOME;
  else process.env.SAFETY_CORE_CONFIG_HOME = originalConfigHome;
  rmSync(configHome, { force: true, recursive: true });
});

describe("OpenCode historical Bash replay adapter", () => {
  test("injects a production-shaped Bash event without executing its command", async () => {
    writeFileSync(join(configHome, "safety-core", "profiles.json"), "{}");

    const result = await replayHistoricalBashEvent({ command: "printf replay-only" });

    expect(result).toEqual({
      command: "printf replay-only",
      policyDecision: "ask",
      policyAllowed: false,
      policyDenied: false,
      reason: null,
    });
    expect(isBashParserInitialized()).toBe(true);
  });

  test("reports a hard-block as a policy denial", async () => {
    writeFileSync(join(configHome, "safety-core", "profiles.json"), "{}");

    const result = await replayHistoricalBashEvent({ command: "cat credentials.json" });

    expect(result.policyDecision).toBe("deny");
    expect(result.policyDenied).toBe(true);
    expect(result.reason).toContain("credentials.json");
  });

  test("keeps replay offline when a judge provider has already been installed", async () => {
    writeFileSync(join(configHome, "safety-core", "profiles.json"), "{}");
    setJudgeProvider(async () => {
      throw new Error("The historical replay must not invoke the judge");
    });

    await expect(replayHistoricalBashEvent({ command: "kubectl get Secret example" })).resolves.toMatchObject({
      policyDecision: "ask",
    });
  });

  test("property: each replay decision has exactly one matching decision flag", async () => {
    writeFileSync(join(configHome, "safety-core", "profiles.json"), JSON.stringify({ ghReadOnly: true }));
    const commands = Array.from({ length: 128 }, (_, index) => [
      "gh issue list", "cat credentials.json", `printf replay-${index}`, "gh issue list; id",
    ][index % 4]!);

    const results = await replayHistoricalBashEvents(commands.map((command) => ({ command })));
    expect(results.map((result) => result.command)).toEqual(commands);
    for (const result of results) {
      expect(Number(result.policyAllowed) + Number(result.policyDenied)).toBeLessThanOrEqual(1);
      expect(result.policyAllowed).toBe(result.policyDecision === "allow");
      expect(result.policyDenied).toBe(result.policyDecision === "deny");
    }
  });
});
