import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";

test("treats an unavailable Bash parser as a deployment assertion failure", () => {
  // Other test files initialize the module-global parser. Exercise this
  // deployment boundary in a fresh Bun process so file scheduling cannot
  // accidentally turn an unavailable-parser regression into a false pass.
  const moduleUrl = new URL("../src/index.ts", import.meta.url).href;
  const result = spawnSync(process.execPath, ["-e", `
    const core = await import(${JSON.stringify(moduleUrl)});
    try {
      core.evaluateBashGuards({ source: "echo harmless" });
      process.exit(1);
    } catch (error) {
      if (!(error instanceof core.BashParserFailure)) process.exit(1);
    }
  `], { encoding: "utf8" });

  expect(result.status).toBe(0);
});
