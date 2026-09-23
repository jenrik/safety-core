import { expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadPolicyRuntime } from "../src/policy/runtime.ts";
import {
  createPolicySessionManifest,
  loadPolicySessionRuntime,
  verifyPolicySessionSnapshot,
} from "../src/policy/session.ts";

const limits = { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 };

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "safety-core-session-"));
  const home = join(root, "home");
  const policy = join(root, "policy.policy.mjs");
  const config = join(home, "safety-core", "config.json");
  const env = { SAFETY_CORE_CONFIG_HOME: home };
  mkdirSync(join(home, "safety-core"), { recursive: true });
  writeFileSync(policy, `export default Object.freeze({ apiVersion: 1, layer: "permission", select: Object.freeze([]), evaluate: () => ({ kind: "ignore" }) });\n`);
  writeFileSync(config, JSON.stringify({ version: 1, policies: [policy], projectPolicies: { mode: "disabled" }, bashAnalysis: limits }));
  return { root, config, policy, env };
}

test("session snapshot records selected root and canonical configuration/source digests", async () => {
  const value = fixture();
  try {
    const runtime = await loadPolicyRuntime(value.root, value.env);
    const manifest = createPolicySessionManifest("session-1", runtime, value.root);

    expect(manifest).toMatchObject({
      version: 1,
      sessionID: "session-1",
      cwd: value.root,
      configurations: [{ canonicalPath: value.config, scope: "global" }],
      sources: [{ canonicalPath: value.policy, scope: "global" }],
    });
    expect(manifest.projectRoot).toBeUndefined();
    expect(manifest.configurations[0]!.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(manifest.sources[0]!.sha256).toMatch(/^[a-f0-9]{64}$/);
    await expect(loadPolicySessionRuntime(manifest)).resolves.toMatchObject({ limits });
  } finally {
    rmSync(value.root, { recursive: true, force: true });
  }
});

test("isolated session hooks hard-fail before loading changed or missing bytes", async () => {
  const value = fixture();
  try {
    const manifest = createPolicySessionManifest("session-2", await loadPolicyRuntime(value.root, value.env), value.root);
    writeFileSync(value.policy, "this is deliberately not valid policy code\n");
    await expect(loadPolicySessionRuntime(manifest)).rejects.toThrow("policy source digest changed since session startup");

    writeFileSync(value.policy, `export default Object.freeze({ apiVersion: 1, layer: "permission", select: Object.freeze([]), evaluate: () => ({ kind: "ignore" }) });\n`);
    writeFileSync(value.config, "{}");
    expect(() => verifyPolicySessionSnapshot(manifest)).toThrow("configuration digest changed since session startup");

    writeFileSync(value.config, JSON.stringify({ version: 1, policies: [value.policy], projectPolicies: { mode: "disabled" }, bashAnalysis: limits }));
    rmSync(value.policy);
    await expect(loadPolicySessionRuntime(manifest)).rejects.toThrow("cannot verify policy source");
  } finally {
    rmSync(value.root, { recursive: true, force: true });
  }
});

test("property: every sampled one-byte source change invalidates the immutable session", async () => {
  const value = fixture();
  try {
    const manifest = createPolicySessionManifest("session-3", await loadPolicyRuntime(value.root, value.env), value.root);
    const original = `export default Object.freeze({ apiVersion: 1, layer: "permission", select: Object.freeze([]), evaluate: () => ({ kind: "ignore" }) });\n`;
    for (let seed = 0; seed < 128; seed++) {
      writeFileSync(value.policy, `${original}// ${String.fromCharCode(33 + seed)}\n`);
      expect(() => verifyPolicySessionSnapshot(manifest), `seed ${seed}`).toThrow("policy source digest changed since session startup");
    }
  } finally {
    rmSync(value.root, { recursive: true, force: true });
  }
});
