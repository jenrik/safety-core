import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";

import { analyzeBashWithPolicies, completePolicyInitialEnvironment, initBundledBashParser } from "../src/index.ts";
import { compilePolicyDocument } from "../src/policy/dsl/compile.ts";
import { createDslPolicy } from "../src/policy/dsl/evaluate.ts";
import { parsePolicyDocument } from "../src/policy/dsl/validate.ts";

const path = new URL("../policies/dsl/nix/nix-prefetch-url.policy.json", import.meta.url);
const policy = createDslPolicy(compilePolicyDocument(parsePolicyDocument(readFileSync(path, "utf8"))), path.pathname);

function decision(args: readonly string[], overrides: Record<string, unknown> = {}): string {
  return policy.evaluate({
    kind: "invocation",
    executable: { kind: "known", value: "nix-prefetch-url" },
    executableIdentity: { qualification: "incomplete", spelling: "nix-prefetch-url", basename: "nix-prefetch-url", chain: [], failure: { kind: "not-found" } },
    argv: args.map((value) => ({ kind: "known" as const, value })),
    environment: {}, missingBindings: "unset", redirects: [], assignments: {},
    span: { start: 0, end: 0 }, provenance: { route: ["direct"] }, inPipeline: false, processEffect: "none",
    ...overrides,
  } as any).kind;
}

function permutations<T>(values: readonly T[]): T[][] {
  if (values.length < 2) return [[...values]];
  return values.flatMap((value, index) => permutations([...values.slice(0, index), ...values.slice(index + 1)]).map((tail) => [value, ...tail]));
}

describe("nix-prefetch-url read-only DSL policy", () => {
  test("permits one reviewed remote URL with an optional expected hash", () => {
    for (const url of [
      "https://example.test/source.tar.gz",
      "HTTPS://EXAMPLE.TEST/source.tar.gz",
      "http://example.test/source.tar.gz",
      "ftp://example.test/source.tar.gz",
      "ftps://example.test/source.tar.gz",
      "mirror://gnu/source.tar.gz",
    ]) {
      expect(decision([url]), url).toBe("allow");
      expect(decision([url, "sha256-deadbeef"]), `${url} hash`).toBe("allow");
    }
  });

  test("property: documented options, values, and placements compose", () => {
    const url = "https://example.test/source.tar.gz";
    for (const hashType of ["blake3", "md5", "sha1", "sha256", "sha512"]) {
      const blocks = [["--type", hashType], ["--name", "source"], ["--print-path"], ["--unpack"], ["--executable"]];
      for (const order of permutations(blocks)) {
        const options = order.flat();
        for (const args of [
          [...options, url, "sha256-deadbeef"],
          [url, ...options, "sha256-deadbeef"],
          [url, "sha256-deadbeef", ...options],
        ]) expect(decision(args), args.join(" ")).toBe("allow");
      }
    }
  });

  test("defers excluded URLs, malformed command grammar, and unresolved input", () => {
    for (const args of [
      [], ["file:///tmp/synthetic-input"], ["FILE:///tmp/synthetic-input"], ["s3://example.test/source"],
      ["https://"], ["https://user@example.test/source"], ["https://example.test/source?token=synthetic"],
      ["https://example.test/source#fragment"], ["https://example.test/source", "extra", "another"],
      ["https://example.test/source", "--"], ["https://example.test/source", "--type"],
      ["https://example.test/source", "--type=sha256"], ["https://example.test/source", "--type", "sha3"],
      ["https://example.test/source", "--unknown"], ["--help"], ["--version"],
    ]) expect(decision(args), args.join(" ")).toBe("defer");

    const unknown = { kind: "unknown", reason: { kind: "expansion" } };
    expect(decision([], { argv: [unknown] })).toBe("defer");
    expect(decision([], { argv: [{ kind: "known", value: "https://example.test/source" }, unknown] })).toBe("defer");
  });

  test("defers modeled shell output, shell routing, and unsafe Nix configuration", () => {
    const args = ["https://example.test/source"];
    expect(decision(args, { redirects: [{ kind: "output", target: { kind: "known", value: "synthetic-output" } }] })).toBe("defer");
    expect(decision(args, { assignments: { NIX_REMOTE: { kind: "known", value: "ssh" } } })).toBe("defer");
    expect(decision(args, { inPipeline: true })).toBe("defer");
    expect(decision(args, { executable: { kind: "known", value: "/usr/bin/nix-prefetch-url" } })).toBe("defer");
    expect(decision(args, { environment: { "__SAFETY_CORE_BASH_FUNCTION_nix-prefetch-url": { kind: "known", value: "present" } } })).toBe("defer");

    for (const name of ["NIX_CONFIG", "NIX_CONF_DIR", "NIX_REMOTE", "NIX_USER_CONF_FILES"]) {
      expect(decision(args, { environment: { [name]: { kind: "known", value: "synthetic" } } }), name).toBe("defer");
      expect(decision(args, { environment: { [name]: { kind: "known", value: "" } } }), `${name}=empty`).toBe("allow");
    }
    expect(decision(args, { missingBindings: "unknown" })).toBe("defer");
  });

  test("permits statically resolved URL bindings and defers unresolved bindings", async () => {
    await initBundledBashParser();
    const resolved = analyzeBashWithPolicies({
      source: 'url=https://example.test/source.tar.gz; nix-prefetch-url "$url"',
      initialEnvironment: completePolicyInitialEnvironment({}),
      policies: [policy],
    });
    expect(resolved.decision).toBe("allow");
    expect(resolved.events).toHaveLength(1);
    expect(resolved.events[0]).toMatchObject({ executable: { kind: "known", value: "nix-prefetch-url" }, argv: [{ kind: "known", value: "https://example.test/source.tar.gz" }] });

    const unresolved = analyzeBashWithPolicies({
      source: 'nix-prefetch-url "$url"',
      initialEnvironment: completePolicyInitialEnvironment({}),
      policies: [policy],
    });
    expect(unresolved.decision).toBe("defer");
  });
});
