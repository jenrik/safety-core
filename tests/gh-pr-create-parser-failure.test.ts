import { expect, test } from "bun:test";

import { analyzeGhPrCreateCommand, type GhPrCreatePolicy } from "../src/index.ts";

const enabledPolicy: GhPrCreatePolicy = {
  enabled: true,
  allowedRepositories: ["acme/widgets"],
  allowedOrganizations: [],
};

test("fails closed with a deployment diagnostic when the Bash parser is unavailable", () => {
  const decision = analyzeGhPrCreateCommand("echo harmless", enabledPolicy);

  expect(decision.kind).toBe("deny");
  expect(decision.kind === "deny" && decision.reason).toContain("damaged safety-core hook deployment");
});
