import { describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { BUILTINS_V1 } from "../src/policy/dsl/builtins.ts";
import { compilePolicyDocument } from "../src/policy/dsl/compile.ts";
import { createDslPolicy } from "../src/policy/dsl/evaluate.ts";
import { parsePolicyDocument } from "../src/policy/dsl/validate.ts";

const strictArtifactPath = new URL("../policies/dsl/strict-kubectl.policy.json", import.meta.url);
const strictArtifact = JSON.parse(readFileSync(strictArtifactPath, "utf8")) as Record<string, any>;
const strictPolicy = createDslPolicy(compilePolicyDocument(parsePolicyDocument(strictArtifact)), strictArtifactPath.pathname);

function strictDryRunDecision(args: readonly string[], overrides: Record<string, unknown> = {}): string {
  return strictPolicy.evaluate({
    kind: "invocation",
    executable: { kind: "known", value: "kubectl" },
    executableIdentity: { qualification: "incomplete", spelling: "kubectl", basename: "kubectl", chain: [], failure: { kind: "not-found" } },
    argv: args.map((value) => ({ kind: "known" as const, value })),
    environment: {},
    missingBindings: "unset",
    redirects: [],
    assignments: {},
    span: { start: 0, end: 0 },
    provenance: { route: ["direct"] },
    inPipeline: false,
    processEffect: "none",
    ...overrides,
  } as any).kind;
}

function builtinCalls(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(builtinCalls);
  if (!value || typeof value !== "object") return [];
  const record = value as Record<string, unknown>;
  return [...(typeof record.call === "string" ? [record.call] : []), ...Object.values(record).flatMap(builtinCalls)];
}

describe("declarative kubectl apply dry-run policy", () => {
  test("uses parsed option registers rather than a raw dry-run argv scan or command-specific builtin", () => {
    expect(BUILTINS_V1).not.toHaveProperty("kubectlApplyDryRunAuthorized");
    expect(JSON.stringify(strictArtifact)).not.toContain("kubectlApplyDryRunAuthorized");
    expect(strictArtifact.folds).not.toHaveProperty("kubectlDryRunCount");
    expect(strictArtifact.registers).toMatchObject({
      kubectlDryRunSeen: { type: "bool", initial: false },
      kubectlDryRunValid: { type: "bool", initial: true },
      kubectlHasFilename: { type: "bool", initial: false },
      kubectlHasKustomize: { type: "bool", initial: false },
    });
    expect(strictArtifact.options.kubectlDryRun).toMatchObject({ names: ["--dry-run"], value: "required", forms: ["equalsLong"] });
    expect(builtinCalls(strictArtifact).every((name) => Object.hasOwn(BUILTINS_V1, name))).toBeTrue();
  });

  test("allows exactly one lowercase equals-form mode, ordinary apply, and one source grammar", () => {
    for (const args of [
      ["apply", "--dry-run=client", "-f", "manifest.yaml"],
      ["--dry-run=server", "apply", "--filename", "-"],
      ["-f", "https://example.test/manifest.yaml", "apply", "--dry-run=client"],
      ["apply", "-k", "plugin-enabled-overlay", "--dry-run=server"],
      ["apply", "--dry-run=client", "-f", "manifests"],
      ["apply", "--dry-run=client", "-Rfmanifest.yaml"],
      ["apply", "--dry-run=server", "--cascade=foreground", "--validate", "--context=", "--namespace=", "-f", "manifest.yaml"],
      ["apply", "--dry-run=client", "--field-manager=", "--selector=", "--subresource=", "--prune-allowlist=", "-f", "manifest.yaml"],
    ]) expect(strictDryRunDecision(args), args.join(" ")).toBe("allow");
  });

  test("property: every declared non-dry-run value option consumes a dry-run-looking value instead of establishing dry-run", () => {
    const values = Object.entries(strictArtifact.options as Record<string, { names: readonly string[]; value: string }>)
      .filter(([name, option]) => name !== "kubectlDryRun" && option.value !== "absent")
      .map(([, option]) => option.names[0]!);
    expect(values.length).toBeGreaterThan(0);
    for (const option of values) {
      const args = ["apply", option, "--dry-run=client", "-f", "manifest.yaml"];
      expect(strictDryRunDecision(args), option).toBe("defer");
    }
  });

  test("property: modes and source forms are ordering-insensitive within the declared grammar", () => {
    const modes = [["--dry-run=client"], ["--dry-run=server"]] as const;
    const inputs = [["-f", "-"], ["--filename", "manifest.yaml"], ["-k", "plugin-overlay"]] as const;
    for (const mode of modes) for (const input of inputs) {
      for (const args of [
        ["apply", ...mode, ...input],
        [...mode, "apply", ...input],
        [...input, "apply", ...mode],
        ["apply", ...input, ...mode],
      ]) expect(strictDryRunDecision(args), args.join(" ")).toBe("allow");
    }
  });

  test("property: every approved boolean is bare and every explicit value defers", () => {
    const booleans = Object.entries(strictArtifact.options as Record<string, { names: readonly string[]; value: string; availableIn: readonly string[] }>)
      .filter(([name, option]) => (name.startsWith("kubectlApplyBoolean") || name.startsWith("kubectlApplyBare")) && option.value === "absent")
      .map(([, option]) => option.names[0]!);
    for (const option of booleans) {
      expect(strictDryRunDecision(["apply", "--dry-run=client", option, "-f", "manifest.yaml"]), option).toBe("allow");
      if (option.startsWith("--")) expect(strictDryRunDecision(["apply", "--dry-run=client", `${option}=maybe`, "-f", "manifest.yaml"]), option).toBe("defer");
    }
  });

  test("defers apply-local bare flags before apply while retaining supported pre-apply value forms", () => {
    for (const args of [
      ["--dry-run=client", "apply", "-f", "manifest.yaml"],
      ["--filename", "manifest.yaml", "apply", "--dry-run=client"],
      ["--cascade=foreground", "apply", "--dry-run=client", "-f", "manifest.yaml"],
      ["--context=dev", "apply", "--dry-run=client", "-f", "manifest.yaml"],
    ]) expect(strictDryRunDecision(args), args.join(" ")).toBe("allow");

    for (const args of [
      ["--force", "apply", "--dry-run=client", "-f", "manifest.yaml"],
      ["--validate", "apply", "--dry-run=client", "-f", "manifest.yaml"],
      ["-R", "apply", "--dry-run=client", "-f", "manifest.yaml"],
    ]) expect(strictDryRunDecision(args), args.join(" ")).toBe("defer");
  });

  test("property: every apply-local bare option is post-apply only", () => {
    const options = Object.entries(strictArtifact.options as Record<string, { names: readonly string[]; value: string; availableIn: readonly string[] }>)
      .filter(([name, option]) => (name.startsWith("kubectlApplyBoolean") || name.startsWith("kubectlApplyBare")) && option.value === "absent");
    expect(options.length).toBe(13);
    for (const [, option] of options) {
      expect(option.availableIn).toEqual(["kubectlApply"]);
      for (const name of option.names) {
        expect(strictDryRunDecision([name, "apply", "--dry-run=client", "-f", "manifest.yaml"]), name).toBe("defer");
        expect(strictDryRunDecision(["apply", name, "--dry-run=client", "-f", "manifest.yaml"]), name).toBe("allow");
      }
    }
  });

  test("defers malformed modes, source grammar failures, positional children, terminators, and unreviewed flags", () => {
    for (const args of [
      ["apply", "--dry-run=Client", "-f", "manifest.yaml"],
      ["apply", "--dry-run=none", "-f", "manifest.yaml"],
      ["apply", "--dry-run", "client", "-f", "manifest.yaml"],
      ["apply", "--dry-run", "server", "-f", "manifest.yaml"],
      ["apply", "--dry-run", "-f", "manifest.yaml"],
      ["apply", "--dry-run=client", "--dry-run=server", "-f", "manifest.yaml"],
      ["apply", "--dry-run=client"],
      ["apply", "--dry-run=client", "-f", ""],
      ["apply", "--dry-run=client", "-k", "overlay", "-f", "manifest.yaml"],
      ["apply", "--dry-run=client", "-k", "overlay", "-R"],
      ["apply", "set-last-applied", "--dry-run=client", "-f", "manifest.yaml"],
      ["apply", "--dry-run=client", "-f", "manifest.yaml", "extra"],
      ["apply", "--dry-run=client", "-f", "manifest.yaml", "--"],
      ["apply", "--", "--dry-run=client", "-f", "manifest.yaml"],
      ["apply", "--dry-run=client", "--force=maybe", "-f", "manifest.yaml"],
      ["apply", "--dry-run=client", "--validate=warn", "-f", "manifest.yaml"],
      ["apply", "--dry-run=client", "--output=json", "-f", "manifest.yaml"],
      ["apply", "--dry-run=client", "--unknown", "-f", "manifest.yaml"],
    ]) expect(strictDryRunDecision(args), args.join(" ")).toBe("defer");
  });

  test("defers unsafe routes even where the native strict profile separately remains conservative", () => {
    const args = ["apply", "--dry-run=client", "-f", "manifest.yaml"];
    expect(strictDryRunDecision(args, { assignments: { KUBECONFIG: { kind: "known", value: "x" } } })).toBe("defer");
    expect(strictDryRunDecision(args, { redirects: [{ kind: "output", target: { kind: "known", value: "out" } }] })).toBe("defer");
    expect(strictDryRunDecision(args, { provenance: { route: ["transparent-wrapper"] } })).toBe("defer");
    expect(strictDryRunDecision(args, { environment: { KUBECONFIG: { kind: "known", value: "x" } } })).toBe("defer");
  });

  test("keeps the generated strict kubectl artifact current", () => {
    const checkedIn = readFileSync(strictArtifactPath, "utf8");
    execFileSync("bun", ["scripts/generate-read-only-dsl.ts"], { cwd: process.cwd(), stdio: "pipe" });
    expect(readFileSync(strictArtifactPath, "utf8")).toBe(checkedIn);
  });
});
