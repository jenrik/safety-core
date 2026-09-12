// Claude Code hook for parsed, credential-safe read-only CLI profiles.

import {
  analyzeGhReadOnlyCommand,
  analyzeHelmReadOnlyCommand,
  analyzeStrictReadOnlyCommand,
  discoverWasmDir,
  initBashParser,
  loadBashAnalysisLimits,
  isProfileEnabled,
} from "../../src/index.js";
import { emitAllow, parseHookEvent, readStdin, run } from "./_shared.js";

run(async () => {
  const strictProfiles = [
    ["argocdReadOnly", "argocd"], ["cosignReadOnly", "cosign"], ["craneReadOnly", "crane"],
    ["dockerReadOnly", "docker"], ["jfrogReadOnly", "jf"], ["jfrogReadOnly", "jfrog"],
    ["kubectlReadOnly", "kubectl"], ["nixReadOnly", "nix"], ["nixEnvReadOnly", "nix-env"],
    ["nixStoreReadOnly", "nix-store"], ["ocReadOnly", "oc"], ["podmanReadOnly", "podman"],
    ["podmanComposeReadOnly", "podman-compose"], ["skopeoReadOnly", "skopeo"],
    ["tofuReadOnly", "tofu"], ["npmReadOnly", "npm"], ["pipReadOnly", "pip"],
    ["uvReadOnly", "uv"], ["yarnReadOnly", "yarn"],
  ] as const;
  if (!isProfileEnabled("ghReadOnly") && !isProfileEnabled("helmReadOnly") && !strictProfiles.some(([profile]) => isProfileEnabled(profile))) return;
  await initBashParser(discoverWasmDir(import.meta.url));

  const event = parseHookEvent(readStdin());
  if (!event || event.tool_name !== "Bash") return;
  const command = (event.tool_input?.command as string | undefined) ?? "";
  const context = bashAuthorizationContext();
  if (isProfileEnabled("ghReadOnly")) {
    const decision = analyzeGhReadOnlyCommand(command, context);
    if (decision.kind === "allow") { emitAllow(decision.reason); return; }
    if (decision.kind !== "ignore") return;
  }
  if (isProfileEnabled("helmReadOnly")) {
    const decision = analyzeHelmReadOnlyCommand(command, context);
    if (decision.kind === "allow") { emitAllow(decision.reason); return; }
    if (decision.kind !== "ignore") return;
  }
  for (const [profile, executable] of strictProfiles) {
    if (!isProfileEnabled(profile)) continue;
    const decision = analyzeStrictReadOnlyCommand(command, executable, context);
    if (decision.kind === "allow") { emitAllow(decision.reason); return; }
    if (decision.kind !== "ignore") return;
  }
});

function bashAuthorizationContext() {
  return Object.freeze({
    limits: loadBashAnalysisLimits(),
    initialEnvironment: { kind: "unavailable" as const },
  });
}
