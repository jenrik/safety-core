import { expect, test } from "bun:test";
import {
  clearJudgeVerdict,
  clearJudgeVerdicts,
  getJudgeVerdict,
  parseJudgeResponse,
  setJudgeVerdict,
} from "../src/index.ts";

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

test("property: judge parsing preserves explicit denials across generated JSON reasons", () => {
  for (let index = 0; index < 100; index++) {
    const reason = `deny-${index}-\"${"x".repeat(index)}`;
    expect(parseJudgeResponse(`before ${JSON.stringify({ ok: false, reason })} after`)).toEqual({
      safe: false,
      reasoning: reason,
      fromLLM: true,
    });
  }
});
