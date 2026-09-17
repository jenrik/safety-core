import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";

import { ghCommandGrammarMatches, ghNativeAliasesForRule, parseGhCommandLine } from "../src/bash/handlers/gh-command-line.ts";
import { POLICY_ENVIRONMENT_ROUTES, policyInitialEnvironment } from "../src/bash/policy-environment.ts";
import {
  GH_HELP_TOPIC_RULES,
  GH_READ_ONLY_RULES,
} from "../src/bash/policies/gh-read-only.ts";
import { renderGhReadOnlyAudit } from "../scripts/render-gh-read-only-audit.ts";

const fixture = JSON.parse(readFileSync(new URL("../data/gh-cli-2.100.0-reference.json", import.meta.url), "utf8")) as {
  commands: Array<{ path: string[]; aliases: string[][]; preview: boolean; kind: string }>;
  helpTopics: Array<{ name: string }>;
  environment: Array<{ name: string }>;
};

describe("ghReadOnly classification manifest", () => {
  test("classifies every independent inventory path exactly once", () => {
    const inventory = fixture.commands.map((command) => command.path.join(" "));
    const manifest = GH_READ_ONLY_RULES.map((rule) => rule.path.join(" "));
    expect(new Set(manifest).size).toBe(manifest.length);
    expect(manifest).toEqual(inventory);
    expect(GH_READ_ONLY_RULES).toHaveLength(238);
  });

  test("records every native alias, entry kind, and preview marker", () => {
    const rules = new Map(GH_READ_ONLY_RULES.map((rule) => [rule.path.join(" "), rule]));
    for (const entry of fixture.commands) {
      const rule = rules.get(entry.path.join(" "))!;
      expect(rule.aliases.map((alias) => alias.join(" ")), entry.path.join(" ")).toEqual(entry.aliases.map((alias) => alias.join(" ")));
      expect(rule.kind).toBe(entry.kind);
      expect(rule.preview).toBe(entry.preview);
    }
  });

  test("gives every rule one complete disposition and concrete rationale", () => {
    for (const rule of GH_READ_ONLY_RULES) {
      expect(["allow", "defer", "owned"]).toContain(rule.disposition);
      expect(rule.rationale.length).toBeGreaterThan(20);
      expect(rule.outputTrust.length).toBeGreaterThan(20);
      expect(rule.evidence).toContain("2.100.0");
      if (rule.disposition === "defer") expect(rule.exclusionReason).toBeDefined();
      else expect(rule.exclusionReason).toBeUndefined();
      if (rule.disposition === "owned") expect(rule.owner).toBeDefined();
    }
    expect(GH_READ_ONLY_RULES.filter((rule) => rule.disposition === "allow")).toEqual([]);
    expect(GH_READ_ONLY_RULES.filter((rule) => rule.disposition === "owned").map((rule) => [rule.path.join(" "), rule.owner])).toEqual([
      ["api", "ghApiReadOnly"], ["pr create", "ghPrCreate"],
    ]);
  });

  test("classifies every documented help topic separately", () => {
    expect(GH_HELP_TOPIC_RULES.map((rule) => rule.name)).toEqual(fixture.helpTopics.map((topic) => topic.name));
    expect(GH_HELP_TOPIC_RULES.every((rule) => rule.disposition === "defer")).toBe(true);
  });

  test("keeps the generated audit document byte-for-byte current", () => {
    const checkedIn = readFileSync(new URL("../docs/gh-read-only-command-audit.md", import.meta.url), "utf8");
    expect(renderGhReadOnlyAudit(fixture as never)).toBe(checkedIn);
  });
});

describe("scoped gh command parser", () => {
  test("selects the longest canonical command path", () => {
    expect(commandPath("repo autolink list")).toBe("repo autolink list");
    expect(commandPath("repo deploy-key list")).toBe("repo deploy-key list");
    expect(commandPath("codespace ports visibility 8080:public")).toBe("codespace ports visibility");
  });

  test("normalizes every documented native alias to its canonical rule", () => {
    for (const rule of GH_READ_ONLY_RULES) {
      for (const alias of ghNativeAliasesForRule(rule)) {
        const parsed = parseGhCommandLine(alias);
        expect(parsed.kind, alias.join(" ")).toBe("command");
        if (parsed.kind === "command") expect(parsed.rule.path).toEqual(rule.path);
      }
    }
    expect(commandPath("at verify artifact")).toBe("attestation verify");
    expect(commandPath("cs stop")).toBe("codespace stop");
    expect(commandPath("skills search query")).toBe("skill search");
    expect(commandPath("a11y")).toBe("accessibility");
  });

  test("keeps dynamic aliases, extensions, unknown commands, and malformed roots invalid", () => {
    for (const args of [
      ["co", "123"], ["my-alias"], ["my-extension", "run"], ["unknown"],
      ["--unknown", "api", "user"], ["pr", "--unknown", "create"], ["--repo"], ["--repo", "-bad", "licenses"],
    ]) expect(parseGhCommandLine(args).kind, args.join(" ")).toBe("invalid");
  });

  test("property: option boundary and malformed forms never become a local metadata allow", () => {
    for (const args of [
      ["--version", "extra"], ["--version=true"], ["--ver"], ["version", "--"], ["version", "--help"],
      ["-R"], ["-R="], ["--repo="], ["--hostname"], ["--hostname="],
      ["--repo", "acme/widgets", "version"], ["version", "--repo", "acme/widgets"],
      ["--repo=acme/widgets", "version"], ["-Racme/widgets", "version"],
    ]) {
      const parsed = parseGhCommandLine(args);
      expect(parsed.kind === "root-version" || (parsed.kind === "command" && parsed.rule.disposition === "allow" && ghCommandGrammarMatches(parsed)), args.join(" ")).toBe(false);
    }
  });

  test("preserves option identity, value, scope, spelling, and position", () => {
    const parsed = parseGhCommandLine(["pr", "--repo=acme/widgets", "create", "--fill"]);
    expect(parsed.kind).toBe("command");
    if (parsed.kind !== "command") return;
    expect(parsed.rule.path.join(" ")).toBe("pr create");
    expect(parsed.options).toEqual([
      { identity: "--repo", spelling: "--repo=", value: "acme/widgets", position: 1, scope: "root" },
      { identity: "--fill", spelling: "--fill", position: 0, scope: "command" },
    ]);
  });

  test("retains exact zero-operand, zero-flag grammars without auto-allowing startup", () => {
    for (const args of [["version"]]) {
      const parsed = parseGhCommandLine(args);
      expect(parsed.kind).toBe("command");
      if (parsed.kind === "command") expect(ghCommandGrammarMatches(parsed)).toBe(true);
    }
    for (const args of [
      ["licenses", "extra"], ["licenses", "--help"], ["version", "extra"], ["--repo", "acme/widgets", "version"],
    ]) {
      const parsed = parseGhCommandLine(args);
      expect(parsed.kind).toBe("command");
      if (parsed.kind === "command") expect(ghCommandGrammarMatches(parsed), args.join(" ")).toBe(false);
    }
  });

  test("preserves the profile ownership matrix", () => {
    const api = parseGhCommandLine(["--repo", "acme/widgets", "api", "user"]);
    const create = parseGhCommandLine(["pr", "-Racme/widgets", "create", "--fill"]);
    expect(api.kind === "command" && api.rule.owner).toBe("ghApiReadOnly");
    expect(create.kind === "command" && create.rule.owner).toBe("ghPrCreate");
  });
});

describe("policy environment manifest", () => {
  test("assesses every documented route and never captures authentication tokens", () => {
    const documented = fixture.environment.map((route) => route.name).sort();
    const reviewed = POLICY_ENVIRONMENT_ROUTES.map((route) => route.name);
    for (const name of documented) expect(reviewed, name).toContain(name);
    const secretNames = ["GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"];
    for (const name of secretNames) {
      expect(POLICY_ENVIRONMENT_ROUTES.find((route) => route.name === name)).toMatchObject({ disposition: "excluded-secret", capture: false });
    }
    const snapshot = policyInitialEnvironment(Object.fromEntries(secretNames.map((name) => [name, `canary-${name}`])));
    expect(snapshot).toEqual({ kind: "verified", values: {} });
    expect(JSON.stringify(snapshot)).not.toContain("canary");
  });

  test("defines present, empty, unset, and unavailable behavior without emitting values", () => {
    expect(policyInitialEnvironment({ GH_PAGER: "" })).toEqual({ kind: "verified", values: { GH_PAGER: "" } });
    const pager = policyInitialEnvironment({ PAGER: "less" });
    expect(pager.kind === "verified" ? Object.keys(pager.values) : []).toEqual(["__SAFETY_CORE_INHERITED_GH_PAGER"]);
    expect(policyInitialEnvironment({})).toEqual({ kind: "verified", values: {} });
    expect(POLICY_ENVIRONMENT_ROUTES.every((route) => route.rationale.length > 0)).toBe(true);
    expect(POLICY_ENVIRONMENT_ROUTES.find((route) => route.name === "GH_TELEMETRY_SAMPLE_RATE")).toMatchObject({ disposition: "defer", capture: true });
  });
});

function commandPath(value: string): string | undefined {
  const parsed = parseGhCommandLine(value.split(" "));
  return parsed.kind === "command" ? parsed.rule.path.join(" ") : undefined;
}
