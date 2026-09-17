import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";

const fixturePath = new URL("../data/gh-cli-2.100.0-reference.json", import.meta.url);
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
  schemaVersion: number;
  metadata: Record<string, string>;
  commands: Array<{ path: string[]; aliases: string[][]; kind: string; usage: string; summary: string; preview: boolean }>;
  helpTopics: Array<{ name: string; summary: string; executable: boolean }>;
  environment: Array<{ name: string }>;
  dynamicRoutes: Array<{ kind: string; route: string; rationale: string }>;
};

describe("GitHub CLI 2.100.0 independent reference", () => {
  test("has pinned source metadata and a valid self-checksum", () => {
    expect(fixture.schemaVersion).toBe(1);
    expect(fixture.metadata).toMatchObject({
      version: "2.100.0",
      tag: "v2.100.0",
      commit: "45437bc7eeeb3359bbfddd1742f79de7652fd3e2",
      capturedAt: "2026-09-16",
      referenceSha256: "04c093647206c49bb3cbeb07ebba168d98064eb296417a9e3b6932fc1fc4f4c2",
      environmentSha256: "59d6f808e95e7aeabd9ece5f8e3d97733701e5a87ede9e8d0f29232514fdb923",
      rootHelpSha256: "8647c5a2d76bfed7a0d94af2b3c30fb1bf0f10bc953951773b3c40710694257b",
      fixtureSha256: "f3591a6e27a2332b4abd66923c50730bbb77ecda651d7e9e9036f4ab36dcf146",
    });
    const { fixtureSha256, ...metadata } = fixture.metadata;
    const canonical = JSON.stringify({ ...fixture, metadata }, null, 2);
    expect(createHash("sha256").update(canonical).digest("hex")).toBe(fixtureSha256);
  });

  test("contains unique, stably ordered commands and native aliases", () => {
    expect(fixture.commands).toHaveLength(238);
    const paths = fixture.commands.map((command) => command.path.join(" "));
    const aliases = fixture.commands.flatMap((command) => command.aliases.map((alias) => alias.join(" ")));
    expect(new Set(paths).size).toBe(paths.length);
    expect(new Set(aliases).size).toBe(aliases.length);
    expect(aliases.some((alias) => paths.includes(alias))).toBe(false);
    expect(paths).toEqual([...paths].sort((left, right) => {
      const a = left.replaceAll(" ", "\0");
      const b = right.replaceAll(" ", "\0");
      return a < b ? -1 : a > b ? 1 : 0;
    }));
    for (const command of fixture.commands) {
      expect(command.path.length).toBeGreaterThan(0);
      expect(command.usage.startsWith(`gh ${command.path.join(" ")}`)).toBe(true);
      expect(command.summary.length).toBeGreaterThan(0);
      expect(["command", "group", "top-level-command", "hidden-command"]).toContain(command.kind);
      expect(typeof command.preview).toBe("boolean");
    }
    expect(fixture.commands.filter((command) => command.kind === "hidden-command").map((command) => command.path.join(" "))).toEqual([
      "accessibility", "actions", "attestation inspect", "auth git-credential", "codespace select",
      "credits", "repo credits", "repo garden", "send-telemetry", "version",
    ]);
    expect(fixture.commands.find((command) => command.path.join(" ") === "accessibility")?.aliases).toEqual([["a11y"]]);
  });

  test("keeps help topics, environment routes, and dynamic routes explicit", () => {
    expect(fixture.helpTopics.map((topic) => topic.name)).toEqual([
      "environment", "exit-codes", "formatting", "mintty", "reference", "telemetry",
    ]);
    expect(fixture.helpTopics.every((topic) => topic.executable && topic.summary.length > 0)).toBe(true);
    expect(fixture.environment).toHaveLength(37);
    expect(fixture.environment.map((route) => route.name)).toEqual(expect.arrayContaining([
      "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
      "GH_CONFIG_DIR", "GH_HOST", "GH_REPO", "GH_PAGER", "PAGER", "HOME", "XDG_CONFIG_HOME",
    ]));
    expect(fixture.dynamicRoutes.map((route) => route.kind)).toEqual([
      "configured-alias", "shipped-default-alias", "installed-extension",
      "official-extension-stub", "official-extension-stub", "official-extension-stub",
    ]);
  });
});
