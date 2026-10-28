import { expect, test } from "bun:test";
import { clearJudgeVerdict, clearJudgeVerdicts, getJudgeVerdict, setJudgeVerdict } from "../src/index.ts";

test("property: judge verdict cleanup removes individual and session verdicts", () => {
  const ids = Array.from({ length: 100 }, (_, index) => `call-${index}`);
  for (const id of ids) setJudgeVerdict(id, { safe: true, reasoning: id });

  for (const id of ids.filter((_, index) => index % 2 === 0)) clearJudgeVerdict(id);
  for (const [index, id] of ids.entries()) {
    if (index % 2 === 0) expect(getJudgeVerdict(id), id).toBeUndefined();
    else expect(getJudgeVerdict(id), id).toBeDefined();
  }

  clearJudgeVerdicts();
  for (const id of ids) expect(getJudgeVerdict(id), id).toBeUndefined();
});
