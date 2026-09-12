import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";

import type { GhPrCreatePolicy } from "../src/index.ts";

const enabledPolicy: GhPrCreatePolicy = {
  enabled: true,
  allowedRepositories: ["acme/widgets"],
  allowedOrganizations: [],
};

test("fails closed with a deployment diagnostic when the Bash parser is unavailable", () => {
  // Other test files initialize the module-global parser. Exercise this
  // deployment boundary in a fresh Bun process so file scheduling cannot
  // accidentally turn an unavailable-parser regression into a false pass.
  const moduleUrl = new URL("../src/index.ts", import.meta.url).href;
  const result = spawnSync(process.execPath, ["-e", `
    const core = await import(${JSON.stringify(moduleUrl)});
    const decision = core.analyzeGhPrCreateCommand("echo harmless", ${JSON.stringify(enabledPolicy)});
    if (decision.kind !== "deny" || !decision.reason.includes("damaged safety-core hook deployment")) process.exit(1);
  `], { encoding: "utf8" });

  expect(result.status).toBe(0);
});
