import { describe, expect, test } from "bun:test";

import {
  assignLocalBinding,
  assignNonLocalBinding,
  assignBinding,
  beginCommandOverlay,
  endCommandOverlay,
  forkCheckpoint,
  fromInitialEnvironment,
  known,
  lookupBinding,
  mergeCheckpoint,
  pushFunctionFrame,
  pushSubshellFrame,
  recordWrite,
  returnFromFunctionFrame,
  setExported,
  setReadonly,
  taintFrame,
  unknown,
  unset,
  unsetBinding,
  type EnvironmentPatch,
} from "../src/bash/environment.ts";

describe("persistent Bash environment", () => {
  test("looks up known, unknown, and explicitly unset bindings", () => {
    const environment = unsetBinding(
      assignBinding(fromInitialEnvironment({ F: "BAR" }), "UNKNOWN", unknown({ kind: "unsupported" })),
      "G",
    );

    expect(lookupBinding(environment, "F").value).toEqual(known("BAR"));
    expect(lookupBinding(environment, "UNKNOWN").value).toEqual(unknown({ kind: "unsupported" }));
    expect(lookupBinding(environment, "MISSING").value).toEqual(unset());
    expect(lookupBinding(environment, "G").value).toEqual(unset());
  });

  test("preserves export and readonly attributes independently of values", () => {
    const environment = setReadonly(setExported(fromInitialEnvironment({ F: "BAR" }), "F", true), "F", true);

    expect(lookupBinding(environment, "F")).toEqual({
      value: known("BAR"),
      exported: true,
      readonly: true,
    });
  });

  test("uses parent lookup and lets function frames shadow without mutating callers", () => {
    const parent = fromInitialEnvironment({ F: "caller" });
    const local = assignLocalBinding(pushFunctionFrame(parent), "F", known("local"));

    expect(lookupBinding(local, "F").value).toEqual(known("local"));
    expect(lookupBinding(parent, "F").value).toEqual(known("caller"));
    expect(lookupBinding(pushFunctionFrame(parent), "F").value).toEqual(known("caller"));
  });

  test("uses explicit locals and dynamic non-local writes across function returns", () => {
    const parent = fromInitialEnvironment({ F: "caller" });
    const local = assignLocalBinding(pushFunctionFrame(parent), "F", known("local"));
    const localUpdated = assignBinding(local, "F", known("local-updated"));

    expect(lookupBinding(localUpdated, "F").value).toEqual(known("local-updated"));
    expect(lookupBinding(returnFromFunctionFrame(localUpdated), "F").value).toEqual(known("caller"));

    const nonLocal = assignNonLocalBinding(pushFunctionFrame(parent), "F", known("caller-updated"));
    expect(lookupBinding(nonLocal, "F").value).toEqual(known("caller-updated"));
    expect(lookupBinding(returnFromFunctionFrame(nonLocal), "F").value).toEqual(known("caller-updated"));
    expect(lookupBinding(parent, "F").value).toEqual(known("caller"));

    const nested = assignBinding(pushFunctionFrame(pushFunctionFrame(parent)), "F", known("nested-updated"));
    expect(lookupBinding(returnFromFunctionFrame(returnFromFunctionFrame(nested)), "F").value)
      .toEqual(known("nested-updated"));
  });

  test("uses an identity-sharing command overlay and discards it after the invocation", () => {
    const base = fromInitialEnvironment({ F: "BAR" });
    const overlay = beginCommandOverlay(base);
    const withD = assignBinding(overlay, "D", known("GAR"));

    expect(overlay.frame).toBe(base.frame);
    expect(overlay.overlay?.parent).toBe(base.frame);
    expect(lookupBinding(withD, "F").value).toEqual(known("BAR"));
    expect(lookupBinding(endCommandOverlay(withD), "D").value).toEqual(unset());
  });

  test("keeps subshell writes isolated through a persistent child frame", () => {
    const parent = fromInitialEnvironment({ F: "caller" });
    const child = assignBinding(pushSubshellFrame(parent), "F", known("child"));

    expect(lookupBinding(child, "F").value).toEqual(known("child"));
    expect(lookupBinding(parent, "F").value).toEqual(known("caller"));
  });

  test("merges only branch writes that agree", () => {
    const base = fromInitialEnvironment({ F: "base", UNCHANGED: "value" });
    const checkpoint = forkCheckpoint(base);
    const left = patch(assignBinding(base, "F", known("agreed")), recordWrite(checkpoint, "F"));
    const right = patch(assignBinding(base, "F", known("agreed")), recordWrite(checkpoint, "F"));
    const merged = mergeCheckpoint(checkpoint, [left, right]);

    expect(checkpoint.base.frame).toBe(base.frame);
    expect(lookupBinding(merged, "F").value).toEqual(known("agreed"));
    expect(lookupBinding(merged, "UNCHANGED").value).toEqual(known("value"));
  });

  test("marks a disagreed branch write unknown without copying unwritten names", () => {
    const base = fromInitialEnvironment({ F: "base", UNCHANGED: "value" });
    const checkpoint = forkCheckpoint(base);
    const left = patch(assignBinding(base, "F", known("left")), recordWrite(checkpoint, "F"));
    const right = patch(assignBinding(base, "F", known("right")), recordWrite(checkpoint, "F"));
    const merged = mergeCheckpoint(checkpoint, [left, right]);

    expect([...left.writes]).toEqual(["F"]);
    expect(lookupBinding(merged, "F").value).toEqual(unknown({ kind: "branch-disagreement" }));
    expect(lookupBinding(merged, "UNCHANGED").value).toEqual(known("value"));
  });

  test("taints frame lookup conservatively while allowing a later deterministic overwrite", () => {
    const base = fromInitialEnvironment({ F: "BAR" });
    const tainted = taintFrame(base);
    const overwritten = assignBinding(tainted, "F", known("replacement"));

    expect(lookupBinding(tainted, "F").value).toEqual(unknown({ kind: "arbitrary-mutation" }));
    expect(lookupBinding(tainted, "MISSING").value).toEqual(unknown({ kind: "arbitrary-mutation" }));
    expect(lookupBinding(overwritten, "F").value).toEqual(known("replacement"));
  });

  test("does not discard a second arbitrary-mutation taint at a branch merge", () => {
    const checkpointBase = assignBinding(taintFrame(fromInitialEnvironment({ F: "original" })), "F", known("restored"));
    const checkpoint = forkCheckpoint(checkpointBase);
    const stable = patch(checkpointBase, checkpoint);
    const reTainted = patch(taintFrame(checkpointBase), checkpoint);

    expect(lookupBinding(mergeCheckpoint(checkpoint, [stable, reTainted]), "F").value).toEqual(
      unknown({ kind: "arbitrary-mutation" }),
    );
  });

  test("keeps an inherited taint version through compaction without inventing another taint", () => {
    const checkpointBase = assignBinding(taintFrame(fromInitialEnvironment({ F: "original" })), "F", known("restored"));
    const checkpoint = forkCheckpoint(checkpointBase);
    let compacted = checkpointBase;
    for (let index = 0; index < 40; index++) compacted = assignBinding(compacted, `WRITE_${index}`, known(`${index}`));

    expect(lookupBinding(mergeCheckpoint(checkpoint, [patch(checkpointBase, checkpoint), patch(compacted, checkpoint)]), "F").value)
      .toEqual(known("restored"));
  });

  test("property: operations are immutable and assignments change only their target frame", () => {
    const random = lcg(0x4d595df4);

    for (let index = 0; index < 256; index++) {
      const target = `${bindingName(random())}_TARGET`;
      const other = `${bindingName(random())}_OTHER`;
      const oldValue = `old-${random()}`;
      const otherValue = `other-${random()}`;
      const newValue = `new-${random()}`;
      const original = fromInitialEnvironment({ [target]: oldValue, [other]: otherValue });
      const child = pushFunctionFrame(original);
      const updated = assignBinding(child, target, known(newValue));

      expect(lookupBinding(original, target).value).toEqual(known(oldValue));
      expect(lookupBinding(original, other).value).toEqual(known(otherValue));
      expect(lookupBinding(child, target).value).toEqual(known(oldValue));
      expect(lookupBinding(updated, target).value).toEqual(known(newValue));
      expect(lookupBinding(updated, other).value).toEqual(known(otherValue));
      expect(child.frame).not.toBe(updated.frame);
    }
  });

  test("property: repeated taint, checkpoints, and compaction remain conservative", () => {
    const random = lcg(0x7f4a7c15);

    for (let index = 0; index < 128; index++) {
      const name = `${bindingName(random())}_TAINTED`;
      const restored = `restored-${random()}`;
      const base = assignBinding(taintFrame(fromInitialEnvironment({ [name]: `old-${random()}` })), name, known(restored));
      const checkpoint = forkCheckpoint(base);
      let reTainted = taintFrame(base);
      for (let write = 0; write < 40; write++) {
        reTainted = assignBinding(reTainted, `${name}_${write}`, known(`${random()}`));
      }

      expect(lookupBinding(mergeCheckpoint(checkpoint, [patch(base, checkpoint), patch(reTainted, checkpoint)]), name).value.kind)
        .toBe("unknown");
    }
  });

  test("rejects attempted mutation of returned snapshots without changing their values", () => {
    const environment = fromInitialEnvironment({ F: "stable" });
    const binding = lookupBinding(environment, "F");

    expect(() => { (environment.budgets as { steps: number }).steps = 0; }).toThrow();
    expect(() => { (environment.frame as { parent?: object }).parent = {}; }).toThrow();
    expect(() => { (binding.value as { value: string }).value = "changed"; }).toThrow();
    expect(lookupBinding(environment, "F").value).toEqual(known("stable"));
    expect(environment.budgets.steps).toBe(100_000);
  });

  test("property: an unwritten unknown binding never becomes known", () => {
    const random = lcg(0x12345678);

    for (let index = 0; index < 256; index++) {
      const unknownName = bindingName(random());
      const writtenName = `${bindingName(random())}W`;
      const base = taintFrame(fromInitialEnvironment({ [unknownName]: `initial-${random()}` }));
      const checkpoint = forkCheckpoint(base);
      const left = patch(assignBinding(base, writtenName, known(`left-${random()}`)), recordWrite(checkpoint, writtenName));
      const right = patch(assignBinding(base, writtenName, known(`right-${random()}`)), recordWrite(checkpoint, writtenName));
      const merged = mergeCheckpoint(checkpoint, [left, right]);

      expect(lookupBinding(merged, unknownName).value.kind).toBe("unknown");
    }
  });

  test("property: deterministic overwrite may replace an unknown value with known", () => {
    const random = lcg(0x8badf00d);

    for (let index = 0; index < 256; index++) {
      const name = bindingName(random());
      const value = `replacement-${random()}`;
      const overwritten = assignBinding(taintFrame(fromInitialEnvironment({ [name]: `old-${random()}` })), name, known(value));

      expect(lookupBinding(overwritten, name).value).toEqual(known(value));
    }
  });

  test("property: every branch merge disagreement is unknown", () => {
    const random = lcg(0xdecafbad);

    for (let index = 0; index < 256; index++) {
      const name = bindingName(random());
      const base = fromInitialEnvironment({ [name]: `base-${random()}` });
      const checkpoint = forkCheckpoint(base);
      const left = patch(assignBinding(base, name, known(`left-${random()}`)), recordWrite(checkpoint, name));
      const right = patch(assignBinding(base, name, known(`right-${random()}`)), recordWrite(checkpoint, name));

      expect(lookupBinding(mergeCheckpoint(checkpoint, [left, right]), name).value).toEqual(
        unknown({ kind: "branch-disagreement" }),
      );
    }
  });
});

function patch(environment: ReturnType<typeof fromInitialEnvironment>, checkpoint: ReturnType<typeof recordWrite>): EnvironmentPatch {
  return { environment, writes: checkpoint.writes };
}

function lcg(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
}

function bindingName(value: number): string {
  return `V${value % 100000}`;
}
