import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { GH_HELP_TOPIC_RULES, GH_READ_ONLY_RULES } from "../src/bash/policies/gh-read-only.ts";

type Node = { children: Map<string, Node>; owner?: "api" | "pr" };

const root: Node = { children: new Map() };
for (const rule of GH_READ_ONLY_RULES) {
  for (const form of [rule.path, ...rule.aliases]) insert(form, rule.owner === "ghApiReadOnly" ? "api" : rule.owner === "ghPrCreate" ? "pr" : undefined);
}
for (const topic of GH_HELP_TOPIC_RULES) insert(["help", topic.name]);
for (const topic of GH_HELP_TOPIC_RULES) insert([topic.name]);

const states: Record<string, unknown> = {};
emit(root, "start");

const document = {
  language: "safety-core/bash-policy-v1",
  layer: "permission",
  select: [{ executable: { projection: "basename", equals: "gh" } }],
  registers: {},
  folds: {},
  options: {
    repo: { names: ["--repo", "-R"], value: "required", forms: ["separate", "attachedShort", "equalsLong", "cluster"], availableIn: "*", set: {} },
    hostname: { names: ["--hostname"], value: "required", forms: ["separate", "equalsLong"], availableIn: "*", set: {} },
  },
  fragments: {},
  start: "start",
  states,
};

const output = resolve(import.meta.dirname, "../policies/dsl/gh-read-only.policy.json");
mkdirSync(resolve(output, ".."), { recursive: true });
writeFileSync(output, `${JSON.stringify(document, null, 2)}\n`);

function insert(words: readonly string[], owner?: "api" | "pr"): void {
  let current = root;
  for (const word of words) {
    const child = current.children.get(word) ?? { children: new Map<string, Node>() };
    current.children.set(word, child);
    current = child;
  }
  if (owner) current.owner = owner;
}

function emit(node: Node, state: string): void {
  const cases: unknown[] = [];
  for (const [word, child] of [...node.children].sort(([left], [right]) => left.localeCompare(right))) {
    const next = `${state}_${word.replace(/[^A-Za-z0-9]/g, "_")}`;
    cases.push({ when: { call: "equals", args: [{ ref: "word" }, word] }, action: { consume: "word", next } });
    emit(child, next);
  }
  states[state] = {
    cases,
    default: { decision: "defer", audit: { invocation: { ref: "event" } } },
    end: node.owner ? { decision: "ignore" } : { decision: "defer", audit: { invocation: { ref: "event" } } },
  };
  if (node.owner) {
    const delegated = { decision: "defer" };
    states[state] = {
      cases: [{ when: true, action: { consume: "word", next: state } }],
      default: delegated,
      end: delegated,
    };
  }
}
