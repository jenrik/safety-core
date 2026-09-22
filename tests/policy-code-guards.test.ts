import { describe, expect, test } from "bun:test";

import githubHttp from "../policies/code/github-http.policy.ts";
import kubectl from "../policies/code/kubectl.policy.ts";
import secretRead from "../policies/code/secret-read.policy.ts";
import unsupportedShellSource from "../policies/code/unsupported-shell-source.policy.ts";
import type { BashPolicyEvent } from "../src/policy/types.ts";

const invocation = (executable: string, argv: readonly string[]): BashPolicyEvent => Object.freeze({
  kind: "invocation" as const,
  executable: Object.freeze({ kind: "known" as const, value: executable }),
  argv: Object.freeze(argv.map((value) => Object.freeze({ kind: "known" as const, value }))),
  redirects: Object.freeze([]),
  environment: Object.freeze({}),
  missingBindings: "unset" as const,
  assignments: Object.freeze({}),
  span: Object.freeze({ start: 0, end: 1 }),
  provenance: Object.freeze({ route: Object.freeze(["direct"] as const) }),
  inPipeline: false,
  processEffect: "none" as const,
});

describe("trusted code baseline guards", () => {
  test("denies only prohibited secret reads and retains exact event data for audit", () => {
    const blocked = invocation("cat", ["credentials.json"]);

    expect(secretRead.evaluate(blocked)).toMatchObject({
      kind: "deny",
      reason: [{ kind: "literal", value: "bash `cat` on 'credentials.json'" }],
      audit: { invocation: blocked },
    });
    expect(secretRead.evaluate(invocation("cat", ["README.md"]))).toEqual({ kind: "ignore" });
    expect(secretRead.evaluate(invocation("echo", ["credentials.json"]))).toEqual({ kind: "ignore" });
  });

  test("denies only direct GitHub HTTP and preserves actual event data for audit", () => {
    const blocked = invocation("curl", ["https://api.github.com/repos/acme/widgets/issues"]);

    expect(githubHttp.evaluate(blocked)).toMatchObject({
      kind: "deny",
      audit: { invocation: blocked },
    });
    expect(githubHttp.evaluate(invocation("curl", ["https://example.test"]))).toEqual({ kind: "ignore" });
    expect(githubHttp.evaluate(invocation("echo", ["https://api.github.com/user"]))).toEqual({ kind: "ignore" });
  });

  test("keeps kubectl safe paths non-authorizing while retaining secret review evidence", () => {
    const review = invocation("kubectl", ["get", "secret", "application"]);

    expect(kubectl.evaluate(review)).toMatchObject({
      kind: "defer",
      audit: { invocation: review },
    });
    expect(kubectl.evaluate(invocation("kubectl", ["get", "pods"]))).toEqual({ kind: "ignore" });
    expect(kubectl.evaluate(invocation("echo", ["get", "secret"]))).toEqual({ kind: "ignore" });
  });

  test("denies unsupported shell source only through its explicit execution gap", () => {
    const gap: BashPolicyEvent = Object.freeze({
      kind: "execution-gap" as const,
      reason: "unsupported-shell-source",
      environment: Object.freeze({}),
      missingBindings: "unset" as const,
      span: Object.freeze({ start: 0, end: 1 }),
      provenance: Object.freeze({ route: Object.freeze(["direct"] as const) }),
      inPipeline: false,
      processEffect: "spawn-and-wait" as const,
    });

    expect(unsupportedShellSource.evaluate(gap)).toMatchObject({ kind: "deny", audit: { gap } });
    expect(unsupportedShellSource.evaluate({ ...gap, reason: "unsupported-execution" })).toEqual({ kind: "ignore" });
  });
});
