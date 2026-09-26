import { expect, test } from "bun:test";

import { createPolicyRuntimeReloader, type LoadedPolicyRuntime } from "../src/index.ts";

function runtime(revision: number): LoadedPolicyRuntime {
  return { revision } as unknown as LoadedPolicyRuntime;
}

test("policy runtime reload keeps the active runtime when a replacement fails", async () => {
  const initial = runtime(0);
  const reloader = createPolicyRuntimeReloader(async (cwd) => {
    if (cwd === "broken") throw new Error("invalid policy");
    return runtime(Number(cwd));
  }, Promise.resolve(initial));

  await expect(reloader.ensure("0")).resolves.toBe(initial);
  await expect(reloader.reload("broken")).rejects.toThrow("invalid policy");
  expect(reloader.current()).toBe(initial);
  await expect(reloader.reload("1")).resolves.toMatchObject({ revision: 1 });
  expect(reloader.current()).toMatchObject({ revision: 1 });
});

test("policy runtime reload lets the most recently requested replacement win", async () => {
  const pending = new Map<string, { resolve: (value: LoadedPolicyRuntime) => void }>();
  const reloader = createPolicyRuntimeReloader((cwd) => new Promise((resolve) => pending.set(cwd, { resolve })), Promise.resolve(runtime(0)));
  await reloader.ensure("initial");

  const first = reloader.reload("1");
  const second = reloader.reload("2");
  pending.get("2")!.resolve(runtime(2));
  await second;
  pending.get("1")!.resolve(runtime(1));
  await first;

  expect(reloader.current()).toMatchObject({ revision: 2 });
});

test("property: failed reloads never replace the last successful runtime across 1,024 sequences", async () => {
  for (let seed = 0; seed < 1_024; seed++) {
    let expected = 0;
    const reloader = createPolicyRuntimeReloader(async (cwd) => {
      const revision = Number(cwd);
      if ((revision * 17 + seed) % 5 === 0) throw new Error("invalid policy");
      return runtime(revision);
    }, Promise.resolve(runtime(expected)));
    await reloader.ensure("0");

    for (let revision = 1; revision <= 1 + (seed % 16); revision++) {
      const succeeds = (revision * 17 + seed) % 5 !== 0;
      await reloader.reload(String(revision)).catch(() => undefined);
      if (succeeds) expected = revision;
      expect(reloader.current(), `seed ${seed}, revision ${revision}`).toMatchObject({ revision: expected });
    }
  }
});
