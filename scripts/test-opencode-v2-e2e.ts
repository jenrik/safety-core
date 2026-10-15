import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const e2e = resolve(root, "e2e/opencode-v2");

async function run(command: string[], cwd: string, env: Record<string, string | undefined> = {}): Promise<string> {
  const child = Bun.spawn(command, {
    cwd,
    env: { ...process.env, ...env },
    stdout: "pipe",
    stderr: "inherit",
  });
  const output = await new Response(child.stdout).text();
  const status = await child.exited;
  if (status !== 0) throw new Error(`${command.join(" ")} failed with status ${status}`);
  return output;
}

const plugin = (await run(["nix", "build", ".#opencodeV2Plugin", "--no-link", "--print-out-paths"], root)).trim();
if (!plugin.startsWith("/nix/store/")) throw new Error("Nix did not produce an OpenCode V2 plugin path");

await run([process.execPath, "install", "--frozen-lockfile"], e2e);

const drive = resolve(e2e, "node_modules/.bin/opencode-drive");
const environment = {
  SAFETY_CORE_E2E_ROOT: root,
  SAFETY_CORE_OPENCODE_V2_PLUGIN: plugin,
};
for (const scenario of ["secret-read", "judge-model-selection", "permission-prompt", "policy-reload"])
  await run([drive, "run", `./${scenario}.ts`], e2e, environment);
