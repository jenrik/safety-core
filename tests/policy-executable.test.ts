import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  analyzeBashWithPolicies,
  initBashParser,
  matchesExecutableSelector,
  resolveExecutableIdentity,
  type BindingValue,
  type ExecutableFilesystem,
  type ExecutableFilesystemLookup,
  type ValidatedBashPolicy,
} from "../src/index.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-policy-executable-"));
const known = (value: string): BindingValue => Object.freeze({ kind: "known", value });
const executable = Object.freeze({ kind: "entry" as const, entry: Object.freeze({ kind: "file" as const, executable: true }) });
const directory = Object.freeze({ kind: "entry" as const, entry: Object.freeze({ kind: "directory" as const }) });
const unavailable = Object.freeze({ kind: "incomplete" as const, failure: "unavailable" as const });

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(existsSync(packagedWasm) ? packagedWasm : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"), join(wasmDir, "tree-sitter-bash.wasm"));
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

describe("executable identity resolution", () => {
  test.each([
    {
      name: "uses PATH in order after a known non-executable candidate",
      spelling: "tool", cwd: "/work", path: "/first:/second", entries: {
        "/first": directory, "/first/tool": file(false), "/second": directory, "/second/tool": executable,
      }, expected: { qualification: "known", selectedPath: "/second/tool", canonicalTarget: "/second/tool" },
    },
    {
      name: "uses empty and relative PATH entries from cwd",
      spelling: "tool", cwd: "/work", path: ":bin", entries: {
        "/work": directory, "/work/tool": file(false), "/work/bin": directory, "/work/bin/tool": executable,
      }, expected: { qualification: "known", selectedPath: "/work/bin/tool", canonicalTarget: "/work/bin/tool" },
    },
    {
      name: "does not skip an incomplete earlier PATH candidate",
      spelling: "tool", cwd: "/work", path: "/first:/second", entries: {
        "/first": directory, "/first/tool": unavailable, "/second": directory, "/second/tool": executable,
      }, expected: { qualification: "incomplete", selectedPath: "/first/tool", failure: { kind: "path-candidate-incomplete", path: "/first/tool", failure: "unavailable" } },
    },
    {
      name: "resolves a direct relative path without PATH",
      spelling: "./bin/tool", cwd: "/work", path: "", entries: {
        "/work": directory, "/work/bin": directory, "/work/bin/tool": executable,
      }, expected: { qualification: "known", selectedPath: "/work/./bin/tool", canonicalTarget: "/work/bin/tool" },
    },
    {
      name: "applies relative symlinks and following dot-dot in kernel order",
      spelling: "bin/../target", cwd: "/work", path: "", entries: {
        "/work": directory, "/work/bin": link("actual/dir"), "/work/actual": directory, "/work/actual/dir": directory, "/work/actual/target": executable,
      }, expected: { qualification: "known", canonicalTarget: "/work/actual/target", chain: ["/work/bin", "/work/actual/target"] },
    },
    {
      name: "preserves a Nix symlink chain",
      spelling: "gh", cwd: "/work", path: "/run/current-system/sw/bin", entries: {
        "/run": directory, "/run/current-system": link("/nix/store/system"), "/nix": directory, "/nix/store": directory, "/nix/store/system": directory, "/nix/store/system/sw": directory, "/nix/store/system/sw/bin": directory, "/nix/store/system/sw/bin/gh": executable,
      }, expected: { qualification: "known", selectedPath: "/run/current-system/sw/bin/gh", canonicalTarget: "/nix/store/system/sw/bin/gh", chain: ["/run/current-system", "/nix/store/system/sw/bin/gh"] },
    },
    {
      name: "retains a broken symlink failure",
      spelling: "/bin/tool", cwd: "/work", path: "", entries: {
        "/bin": directory, "/bin/tool": link("missing"),
      }, expected: { qualification: "incomplete", failure: { kind: "broken-symlink", path: "/bin/missing" } },
    },
    {
      name: "retains a symlink loop failure",
      spelling: "/a", cwd: "/work", path: "", entries: {
        "/a": link("/b"), "/b": link("/a"),
      }, expected: { qualification: "incomplete", failure: { kind: "symlink-loop", path: "/a" } },
    },
    {
      name: "treats absolute root and terminal directory slashes as directories",
      spelling: "/", cwd: "/work", path: "", entries: { "/": directory },
      expected: { qualification: "incomplete", selectedPath: "/", failure: { kind: "directory", path: "/" } },
    },
    {
      name: "treats an absolute terminal slash as a directory requirement",
      spelling: "/bin/", cwd: "/work", path: "", entries: { "/bin": directory },
      expected: { qualification: "incomplete", selectedPath: "/bin/", failure: { kind: "directory", path: "/bin" } },
    },
    {
      name: "treats a relative terminal slash as a directory requirement",
      spelling: "bin/", cwd: "/work", path: "", entries: { "/work": directory, "/work/bin": directory },
      expected: { qualification: "incomplete", selectedPath: "/work/bin/", failure: { kind: "directory", path: "/work/bin" } },
    },
    {
      name: "retains permission, I/O, and mutation failures",
      spelling: "/tool", cwd: "/work", path: "", entries: { "/tool": Object.freeze({ kind: "incomplete" as const, failure: "permission" as const }) },
      expected: { qualification: "incomplete", failure: { kind: "filesystem", path: "/tool", failure: "permission" } },
    },
    {
      name: "retains an I/O failure",
      spelling: "/tool", cwd: "/work", path: "", entries: { "/tool": Object.freeze({ kind: "incomplete" as const, failure: "io" as const }) },
      expected: { qualification: "incomplete", failure: { kind: "filesystem", path: "/tool", failure: "io" } },
    },
    {
      name: "retains a mutation failure",
      spelling: "/tool", cwd: "/work", path: "", entries: { "/tool": Object.freeze({ kind: "incomplete" as const, failure: "mutation" as const }) },
      expected: { qualification: "incomplete", failure: { kind: "filesystem", path: "/tool", failure: "mutation" } },
    },
  ])("$name", ({ spelling, cwd, path, entries, expected }) => {
    const first = fakeFilesystem(entries);
    const second = fakeFilesystem(entries);
    const identity = resolveExecutableIdentity(spelling, { PATH: known(path) }, cwd, first);
    expect(identity).toMatchObject(expected);
    expect(resolveExecutableIdentity(spelling, { PATH: known(path) }, cwd, second)).toEqual(identity);
    expect(second.transcript).toEqual(first.transcript);
  });

  test("preserves exact loop and depth failures from the first PATH candidate", () => {
    const loop = resolveExecutableIdentity("tool", { PATH: known("/loop:/second") }, "/work", fakeFilesystem({
      "/loop": directory, "/loop/tool": link("/loop/tool"), "/second": directory, "/second/tool": executable,
    }));
    expect(loop).toMatchObject({
      qualification: "incomplete", selectedPath: "/loop/tool", failure: { kind: "symlink-loop", path: "/loop/tool" },
    });

    const links: Record<string, ExecutableFilesystemLookup> = { "/links": directory, "/links/tool": link("/links/0") };
    for (let index = 0; index <= 40; index++) links[`/links/${index}`] = link(String(index + 1));
    const depth = resolveExecutableIdentity("tool", { PATH: known("/links:/second") }, "/work", fakeFilesystem(links));
    expect(depth).toMatchObject({
      qualification: "incomplete", selectedPath: "/links/tool", failure: { kind: "symlink-depth", path: "/links/39" },
    });
  });

  test("uses exact, case-sensitive selector matching without path-derived matches from incomplete identities", () => {
    const identity = resolveExecutableIdentity("gh", { PATH: known("/run/current-system/sw/bin") }, "/work", fakeFilesystem({
      "/run": directory, "/run/current-system": link("/nix/store/system"), "/nix": directory, "/nix/store": directory, "/nix/store/system": directory, "/nix/store/system/sw": directory, "/nix/store/system/sw/bin": directory, "/nix/store/system/sw/bin/gh": executable,
    }));
    expect(matchesExecutableSelector(identity, { kind: "executable-basename", value: "gh" })).toBeTrue();
    expect(matchesExecutableSelector(identity, { kind: "executable-selected-path", value: "/run/current-system/sw/bin/gh" })).toBeTrue();
    expect(matchesExecutableSelector(identity, { kind: "executable-canonical-target", value: "/nix/store/system/sw/bin/gh" })).toBeTrue();
    expect(matchesExecutableSelector(identity, { kind: "executable-chain-contains", value: "/run/current-system" })).toBeTrue();
    expect(matchesExecutableSelector(identity, { kind: "executable-basename", value: "GH" })).toBeFalse();
    expect(matchesExecutableSelector(identity, { kind: "executable-chain-contains", value: "/nix/store" })).toBeFalse();

    const incomplete = resolveExecutableIdentity("gh", { PATH: known("/first:/run/current-system/sw/bin") }, "/work", fakeFilesystem({
      "/first": directory, "/first/gh": unavailable,
    }));
    expect(matchesExecutableSelector(incomplete, { kind: "executable-basename", value: "gh" })).toBeTrue();
    expect(matchesExecutableSelector(incomplete, { kind: "executable-canonical-target", value: "/nix/store/system/sw/bin/gh" })).toBeFalse();
  });

  test("projection permits an exact known target but does not let added ambiguity create that allow", () => {
    const policy: ValidatedBashPolicy = Object.freeze({
      source: Object.freeze({ canonicalPath: "/policies/target.policy.mjs" }),
      layer: "permission",
      select: Object.freeze([{ kind: "executable-canonical-target", value: "/nix/gh" }]),
      evaluate: () => Object.freeze({ kind: "allow", reason: Object.freeze([{ kind: "literal", value: "target" }]) }),
    });
    const base = analyzeBashWithPolicies({
      source: "gh status", initialEnvironment: { kind: "verified", values: { PATH: "/bin" } }, policies: [policy], cwd: "/work",
      executableFilesystem: fakeFilesystem({ "/bin": directory, "/bin/gh": link("/nix/gh"), "/nix": directory, "/nix/gh": executable }),
    });
    const ambiguous = analyzeBashWithPolicies({
      source: "gh status", initialEnvironment: { kind: "verified", values: { PATH: "/first:/bin" } }, policies: [policy], cwd: "/work",
      executableFilesystem: fakeFilesystem({ "/first": directory, "/first/gh": unavailable, "/bin": directory, "/bin/gh": link("/nix/gh"), "/nix": directory, "/nix/gh": executable }),
    });
    expect(base.decision).toBe("allow");
    expect(ambiguous.decision).toBe("defer");
    expect(onlyInvocation(ambiguous).executableIdentity).toMatchObject({ qualification: "incomplete", failure: { kind: "path-candidate-incomplete" } });
  });

  test("property: adding an incomplete earlier candidate never creates a path-dependent match", () => {
    for (let index = 0; index < 128; index++) {
      const command = `tool-${index}`;
      const target = `/nix/store/tool-${index}`;
      const base = resolveExecutableIdentity(command, { PATH: known("/bin") }, "/work", fakeFilesystem({
        "/bin": directory, [`/bin/${command}`]: link(target), "/nix": directory, "/nix/store": directory, [target]: executable,
      }));
      const ambiguous = resolveExecutableIdentity(command, { PATH: known("/first:/bin") }, "/work", fakeFilesystem({
        "/first": directory, [`/first/${command}`]: unavailable, "/bin": directory, [`/bin/${command}`]: link(target), "/nix": directory, "/nix/store": directory, [target]: executable,
      }));
      expect(matchesExecutableSelector(base, { kind: "executable-canonical-target", value: target }), String(index)).toBeTrue();
      expect(matchesExecutableSelector(ambiguous, { kind: "executable-canonical-target", value: target }), String(index)).toBeFalse();
    }
  });

  test("retains symlink-depth and offline-resolution outcomes without host lookup", () => {
    const links: Record<string, ExecutableFilesystemLookup> = {};
    for (let index = 0; index <= 40; index++) links[`/links/${index}`] = link(String(index + 1));
    links["/links"] = directory;
    expect(resolveExecutableIdentity("/links/0", {}, "/work", fakeFilesystem(links))).toMatchObject({
      qualification: "incomplete", failure: { kind: "symlink-depth", path: "/links/40" },
    });

    const offline = analyzeBashWithPolicies({
      source: "gh status", initialEnvironment: { kind: "verified", values: { PATH: "/bin" } }, policies: [], cwd: "/unrelated-host-path",
    });
    expect(onlyInvocation(offline).executableIdentity).toEqual({
      qualification: "incomplete", spelling: "gh", basename: "gh", chain: [], failure: { kind: "path-candidate-incomplete", path: "/bin/gh", failure: "unavailable" }, selectedPath: "/bin/gh",
    });
  });
});

function fakeFilesystem(entries: Readonly<Record<string, ExecutableFilesystemLookup>>): ExecutableFilesystem & { readonly transcript: string[] } {
  const transcript: string[] = [];
  return Object.freeze({
    transcript,
    lstat(path: string): ExecutableFilesystemLookup {
      transcript.push(path);
      return entries[path] ?? Object.freeze({ kind: "missing" });
    },
  });
}

function file(executableFile: boolean): ExecutableFilesystemLookup {
  return Object.freeze({ kind: "entry", entry: Object.freeze({ kind: "file", executable: executableFile }) });
}

function link(target: string): ExecutableFilesystemLookup {
  return Object.freeze({ kind: "entry", entry: Object.freeze({ kind: "symlink", target }) });
}

function onlyInvocation(result: ReturnType<typeof analyzeBashWithPolicies>) {
  const event = result.events.find((value) => value.kind === "invocation");
  if (!event || event.kind !== "invocation") throw new Error("Expected invocation");
  return event;
}
