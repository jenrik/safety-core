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
    writeConfig({});

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
    const guard = join(configHome, "secret-read.policy.mjs");
    writeFileSync(guard, `export default Object.freeze({ apiVersion: 1, layer: "guard", select: Object.freeze([]), evaluate: (event) => event.kind === "invocation" && event.executable?.kind === "known" && event.executable.value === "cat" && event.argv.some((word) => word.kind === "known" && word.value === "credentials.json") ? Object.freeze({ kind: "deny", reason: Object.freeze([{ kind: "literal", value: "protected read" }]) }) : Object.freeze({ kind: "ignore" }) });\n`);
    writeConfig({ policies: [guard] });

    const result = await replayHistoricalBashEvent({ command: "cat credentials.json" });

    expect(result.policyDecision).toBe("deny");
    expect(result.policyDenied).toBe(true);
    expect(result.reason).toContain("protected read");
  });

  test("keeps replay offline when a judge provider has already been installed", async () => {
    writeConfig({});
    setJudgeProvider(async () => {
      throw new Error("The historical replay must not invoke the judge");
    });

    await expect(replayHistoricalBashEvent({ command: "kubectl get Secret example" })).resolves.toMatchObject({
      policyDecision: "ask",
    });
  });

  test("property: each replay decision has exactly one matching decision flag", async () => {
    writeConfig({});
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

function writeConfig(value: Readonly<Record<string, unknown>>): void {
  writeFileSync(join(configHome, "safety-core", "config.json"), JSON.stringify({
    version: 1,
    policies: [],
    projectPolicies: { mode: "disabled" },
    bashAnalysis: { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 },
    ...value,
  }));
}
