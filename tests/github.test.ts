import { expect, test } from "bun:test";

import { buildFallbackGithubBlock, buildGithubSuggestion } from "../src/index.ts";

test("raw GitHub content steering distinguishes the gh API fallback from native subcommands", () => {
  const suggestion = buildGithubSuggestion(
    "https://raw.githubusercontent.com/NixOS/nixpkgs/0954f7ee2f6bb3dc7d4e3d0d8bcb8fd4bde4cfc5/pkgs/by-name/pi/pi-coding-agent/package.nix",
  );

  expect(suggestion).toContain("Use the GitHub CLI, not direct HTTP.");
  expect(suggestion).toContain("`gh` has no native subcommand for reading one file");
  expect(suggestion).toContain(
    "gh api 'repos/NixOS/nixpkgs/contents/pkgs/by-name/pi/pi-coding-agent/package.nix?ref=0954f7ee2f6bb3dc7d4e3d0d8bcb8fd4bde4cfc5'",
  );
  expect(suggestion).toContain("gh repo clone NixOS/nixpkgs /tmp/agent/nixpkgs -- --filter=blob:none");
  expect(suggestion).not.toContain("git clone");
});

test("property: raw GitHub steering preserves every parsed route across 1,024 URLs", () => {
  for (let seed = 0; seed < 1_024; seed++) {
    const owner = `owner-${seed.toString(36)}`;
    const repo = `repo-${(seed * 17).toString(36)}`;
    const ref = `ref-${(seed * 31).toString(36)}`;
    const path = `nested-${seed % 7}/file-${seed.toString(36)}.nix`;
    const suggestion = buildGithubSuggestion(`https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${path}`);

    expect(suggestion, `seed ${seed}`).toContain(`gh api 'repos/${owner}/${repo}/contents/${path}?ref=${ref}'`);
    expect(suggestion, `seed ${seed}`).toContain(
      `gh repo clone ${owner}/${repo} /tmp/agent/${repo} -- --filter=blob:none`,
    );
    expect(suggestion, `seed ${seed}`).not.toContain("git clone");
  }
});

test("fallback GitHub steering also uses the native clone subcommand", () => {
  const suggestion = buildFallbackGithubBlock("raw.githubusercontent.com");

  expect(suggestion).toContain("gh has no native file-read subcommand");
  expect(suggestion).toContain("gh repo clone <owner>/<repo> /tmp/agent/<repo> -- --filter=blob:none");
  expect(suggestion).not.toContain("git clone");
});
