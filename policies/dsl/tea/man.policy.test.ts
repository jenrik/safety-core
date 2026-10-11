import { expect } from "bun:test";

import { policyTestForFile } from "../../../src/policy/testing.ts";

const policyTest = policyTestForFile(import.meta.url);
const profile = { config: "tea-read-only.config.json" };

policyTest.test("allows only the exact bare man route", profile, ({ evaluate }) => {
  expect(evaluate("tea man").decision).toBe("allow");
  for (const command of [
    "tea man topic",
    "tea man -o page.1",
    "tea man --out page.1",
    "tea man --out=page.1",
    "tea man --out=",
    "tea man --out",
    "tea man -opage.1",
    "tea man -o",
    "tea man --output page.1",
    "tea --output json man",
  ])
    expect(evaluate(command).decision, command).toBe("defer");
});

policyTest.property(
  "every man argument keeps the route prompt-gated",
  { ...profile, cases: 32, seed: 71 },
  ({ evaluate, random }) => {
    const command = `tea man ${random.pick(["-o out", "--out out", "--out=out", "--out=", "--out", "-oout", "-o", "--output out", "topic"])}`;
    expect(evaluate(command).decision, command).toBe("defer");
  },
);
