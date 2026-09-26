# OpenCode2 Integration Implementation Plan

> **Implementation update (2026-09-26):** The v1 artifact reuse described
> below was superseded by a direct, separately packaged OpenCode v2 adapter.
> The two adapters intentionally have matching behavior today.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend safety-core's OpenCode safety plugin and `readOnlyBash` permission profile to OpenCode2 (nixos-config's experimental, config-isolated OpenCode build), fixing the shared-profile-config resolution bug that OpenCode2's `XDG_CONFIG_HOME` override would otherwise cause.

**Architecture:** Three self-contained changes. (1) `src/config.ts` gains a `SAFETY_CORE_CONFIG_HOME` override so the shared `profiles.json` lookup survives a harness overriding `XDG_CONFIG_HOME` for its own isolation. (2) `nix/permissions.nix` gains a third `readOnlyBash` target for nixos-config's `modules.opencode2.settings`. (3) In `nixos-config`, OpenCode2's home-manager module is wired to symlink the existing (unmodified) `opencodePluginFile` output and export the new override env var. Each change lands with its own runtime/eval check before commit.

**Tech Stack:** TypeScript (Node 22, ESM), Nix (flake checks, home-manager modules), esbuild (existing bundling, untouched).

## Global Constraints

- The override env var is named exactly `SAFETY_CORE_CONFIG_HOME`. Precedence: `SAFETY_CORE_CONFIG_HOME` → `XDG_CONFIG_HOME` → `~/.config` (`$HOME/.config`).
- `adapters/opencode.ts` and `package.nix`'s `opencodePluginFile` output are **not modified** — they're reused as-is for OpenCode2 (see design spec, "Change 2").
- The `readOnlyBash` profile for OpenCode2 reuses the existing `programs.safetyCorePermissions.profiles.readOnlyBash.enable` toggle. No new option is introduced anywhere.
- `nix/permissions.nix`'s new OpenCode2 branch references nixos-config's private `modules.opencode2` option directly. This is a deliberate, documented coupling (see spec) — leave the explanatory comment in place.
- In `nixos-config`, per that repo's `CLAUDE.md`: files must be `git add`ed before any `nix` command can see them.
- Do not run `scripts/rebuild.sh` or otherwise switch/deploy the live system as part of this plan — verification is evaluation/build-only.
- This repo (`safety-core`) has no unit-test framework; correctness is verified via `flake.nix`'s `checks` (existing convention: `pkgs.runCommand` shell assertions, or pure-Nix `assert`s for module-eval checks).

---

### Task 1: `SAFETY_CORE_CONFIG_HOME` override in `src/config.ts`

**Files:**
- Modify: `src/config.ts:15-19`
- Modify: `flake.nix:43-69` (insert a new check after `gh-api-hook-runtime`)

**Interfaces:**
- Produces: `defaultProfileConfigPath(): string` (unchanged signature, `src/config.ts:16`) — now checks `process.env.SAFETY_CORE_CONFIG_HOME` before `process.env.XDG_CONFIG_HOME`.

- [ ] **Step 1: Add the failing check to `flake.nix`**

Open `flake.nix`. Insert a new attribute into the `checks = forAllSystems (system: let ... in { ... });` block, immediately after the closing `'';` of `gh-api-hook-runtime` (currently `flake.nix:69`) and before the block's closing `});` (currently `flake.nix:70`):

```nix
          gh-api-hook-safety-core-config-home-override = pkgs.runCommand "safety-core-gh-api-hook-config-home-override-check" { } ''
            set -e

            # SAFETY_CORE_CONFIG_HOME must win over XDG_CONFIG_HOME, simulating a
            # harness (OpenCode2) that overrides XDG_CONFIG_HOME for its own config
            # isolation but still needs safety-core's shared profile toggle to work.
            mkdir -p override-config/safety-core decoy-config/safety-core
            echo '{"ghApiReadOnly":true}' > override-config/safety-core/profiles.json
            echo '{"ghApiReadOnly":false}' > decoy-config/safety-core/profiles.json

            export SAFETY_CORE_CONFIG_HOME="$PWD/override-config"
            export XDG_CONFIG_HOME="$PWD/decoy-config"

            allow_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh api user"}}'
            allow_out=$(echo "$allow_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/gh_api_read_allow.mjs)

            if ! echo "$allow_out" | grep -q '"permissionDecision":"allow"'; then
              echo "expected SAFETY_CORE_CONFIG_HOME to take precedence over XDG_CONFIG_HOME, got: $allow_out" >&2
              exit 1
            fi

            touch $out
          '';
```

The full `checks` block should now read (only the new attribute is added, nothing else changes):

```nix
      checks = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          sc = pkgs.callPackage ./package.nix { };
        in {
          hooks-runtime = pkgs.runCommand "safety-core-hooks-runtime-check" { } ''
            ...
          '';

          gh-api-hook-runtime = pkgs.runCommand "safety-core-gh-api-hook-runtime-check" { } ''
            ...
          '';

          gh-api-hook-safety-core-config-home-override = pkgs.runCommand "safety-core-gh-api-hook-config-home-override-check" { } ''
            ... (as above)
          '';
        });
```

- [ ] **Step 2: Run the check and confirm it fails**

```bash
git add flake.nix
nix build .#checks.x86_64-linux.gh-api-hook-safety-core-config-home-override -L --no-link
```

Expected: build fails, with the check's own error printed:
```
expected SAFETY_CORE_CONFIG_HOME to take precedence over XDG_CONFIG_HOME, got:
```
(The `gh_api_read_allow.mjs` hook currently reads only `XDG_CONFIG_HOME`, which points at the decoy config with `ghApiReadOnly: false`, so it emits no `"permissionDecision":"allow"` output — the `grep -q` fails.)

- [ ] **Step 3: Implement the `SAFETY_CORE_CONFIG_HOME` override**

In `src/config.ts`, replace lines 15-19:

```ts
/** Default profile-config path under $XDG_CONFIG_HOME (falling back to ~/.config). */
export function defaultProfileConfigPath(): string {
  const base = process.env.XDG_CONFIG_HOME ?? join(process.env.HOME ?? "", ".config");
  return join(base, "safety-core", "profiles.json");
}
```

with:

```ts
/**
 * Default profile-config path under $SAFETY_CORE_CONFIG_HOME, falling back
 * to $XDG_CONFIG_HOME, then ~/.config. SAFETY_CORE_CONFIG_HOME lets a
 * harness that overrides XDG_CONFIG_HOME for its own config isolation (e.g.
 * OpenCode2) still point safety-core at its real, shared profile config.
 */
export function defaultProfileConfigPath(): string {
  const base =
    process.env.SAFETY_CORE_CONFIG_HOME ??
    process.env.XDG_CONFIG_HOME ??
    join(process.env.HOME ?? "", ".config");
  return join(base, "safety-core", "profiles.json");
}
```

- [ ] **Step 4: Run the check and confirm it passes**

```bash
nix build .#checks.x86_64-linux.gh-api-hook-safety-core-config-home-override -L --no-link
```

Expected: build succeeds (no output, exit 0).

- [ ] **Step 5: Confirm no regression in the existing checks**

```bash
nix build .#checks.x86_64-linux.hooks-runtime .#checks.x86_64-linux.gh-api-hook-runtime -L --no-link
```

Expected: both succeed.

- [ ] **Step 6: Commit**

```bash
git add src/config.ts flake.nix
git commit -m "config: add SAFETY_CORE_CONFIG_HOME override for isolated-XDG harnesses"
```

---

### Task 2: `readOnlyBash` profile for OpenCode2 in `nix/permissions.nix`

**Files:**
- Modify: `nix/permissions.nix:1-22` (header comment) and `nix/permissions.nix:62-69` (readOnlyBash block)
- Modify: `flake.nix` (insert a new check)

**Interfaces:**
- Consumes: `readOnlyBashCommands` (`nix/permissions.nix:27`, already in scope — a list of command-name strings loaded from `data/read-only-bash-commands.json`).
- Produces: when `programs.safetyCorePermissions.profiles.readOnlyBash.enable = true`, sets `config.modules.opencode2.settings.permission.bash` to an attrset of `"<cmd> *" = "allow";` entries, one per command in `readOnlyBashCommands`.

- [ ] **Step 1: Add the failing eval check to `flake.nix`**

Add `lib = pkgs.lib;` to the `let` bindings of the `checks` block (`flake.nix:22-24`), so it reads:

```nix
        let
          pkgs = pkgsFor system;
          lib = pkgs.lib;
          sc = pkgs.callPackage ./package.nix { };
        in {
```

Then insert a new check attribute (after the one added in Task 1):

```nix
          readonly-bash-opencode2-eval =
            let
              stub = { lib, ... }: {
                options = {
                  xdg.configFile = lib.mkOption { type = lib.types.attrsOf lib.types.anything; default = { }; };
                  programs.claude-code.settings = lib.mkOption { type = lib.types.anything; default = { }; };
                  programs.opencode.settings = lib.mkOption { type = lib.types.anything; default = { }; };
                  modules.opencode2.settings = lib.mkOption { type = lib.types.anything; default = { }; };
                };
              };
              evaled = lib.evalModules {
                modules = [
                  stub
                  ./nix/permissions.nix
                  { config.programs.safetyCorePermissions.profiles.readOnlyBash.enable = true; }
                ];
              };
              bashAllow = evaled.config.modules.opencode2.settings.permission.bash;
            in
            assert bashAllow ? "cat *";
            assert bashAllow."cat *" == "allow";
            pkgs.runCommand "safety-core-readonlybash-opencode2-eval-check" { } "touch $out";
```

This is a pure-Nix module-evaluation check (no shell script): it loads `nix/permissions.nix` with `readOnlyBash.enable = true` against a minimal stub of the external options it targets, and asserts the resulting `modules.opencode2.settings.permission.bash` attrset contains `"cat *" = "allow"`. This technique (and the exact stub shape) has been hand-verified against the current file with `nix eval --impure --json -f <scratch>.nix` before writing this plan — `programs.opencode.settings.permission.bash` and `programs.claude-code.settings.permissions.allow` both evaluate correctly through it today.

- [ ] **Step 2: Run the check and confirm it fails**

```bash
git add flake.nix
nix build .#checks.x86_64-linux.readonly-bash-opencode2-eval -L --no-link
```

Expected: eval-time failure — `modules.opencode2.settings.permission.bash` doesn't exist yet on the `mkMerge` branch in `nix/permissions.nix`, so `bashAllow ? "cat *"` is `false` and the `assert` throws (`assertion ... failed`).

- [ ] **Step 3: Add the OpenCode2 branch to `nix/permissions.nix`**

Replace the module's header comment (`nix/permissions.nix:1-22`) — line 4 currently reads:

```nix
# rules that gets rendered into (or consulted at runtime by) the harnesses
# it targets -- currently Claude Code and OpenCode.
```

Change to:

```nix
# rules that gets rendered into (or consulted at runtime by) the harnesses
# it targets -- currently Claude Code, OpenCode, and OpenCode2.
```

And lines 11-13 currently read:

```nix
# `pkgs.safety-core.claudeCodeHooks`) into that directory. Same for OpenCode: its
# plugin wiring is untouched here, since adapters/opencode.ts's new gh-api check
# ships as part of the existing, already-wired safety-core plugin file.
```

Change to:

```nix
# `pkgs.safety-core.claudeCodeHooks`) into that directory. Same for OpenCode
# and OpenCode2: their plugin wiring is untouched here, since
# adapters/opencode.ts's gh-api check ships as part of the existing,
# already-wired safety-core plugin file for both.
```

Then replace lines 62-69:

```nix
    (mkIf cfg.profiles.readOnlyBash.enable {
      programs.claude-code.settings.permissions.allow =
        map (cmd: "Bash(${cmd}:*)") readOnlyBashCommands;

      programs.opencode.settings.permission.bash =
        listToAttrs (map (cmd: nameValuePair "${cmd} *" "allow") readOnlyBashCommands);
    })
```

with:

```nix
    (mkIf cfg.profiles.readOnlyBash.enable {
      programs.claude-code.settings.permissions.allow =
        map (cmd: "Bash(${cmd}:*)") readOnlyBashCommands;

      programs.opencode.settings.permission.bash =
        listToAttrs (map (cmd: nameValuePair "${cmd} *" "allow") readOnlyBashCommands);

      # Coupled to nixos-config's private `modules.opencode2` option, not a
      # generic external home-manager module like `programs.opencode` --
      # acceptable only because nixos-config is safety-core's sole consumer
      # today (see flake.nix's homeManagerModules.default). Revisit if
      # safety-core ever gains a second consumer.
      modules.opencode2.settings.permission.bash =
        listToAttrs (map (cmd: nameValuePair "${cmd} *" "allow") readOnlyBashCommands);
    })
```

- [ ] **Step 4: Run the check and confirm it passes**

```bash
nix build .#checks.x86_64-linux.readonly-bash-opencode2-eval -L --no-link
```

Expected: build succeeds.

- [ ] **Step 5: Confirm no regression in the existing checks**

```bash
nix build .#checks.x86_64-linux.hooks-runtime .#checks.x86_64-linux.gh-api-hook-runtime .#checks.x86_64-linux.gh-api-hook-safety-core-config-home-override -L --no-link
```

Expected: all succeed.

- [ ] **Step 6: Commit**

```bash
git add nix/permissions.nix flake.nix
git commit -m "permissions: extend readOnlyBash profile to OpenCode2"
```

---

### Task 3: Wire the safety plugin and override into `nixos-config`'s OpenCode2 module

**Files (in the `nixos-config` repo, at `/home/user/projects/nixos-config`):**
- Modify: `modules/home-manager/llm/opencode2/default.nix`

**Interfaces:**
- Consumes: `pkgs.safety-core.opencodePluginFile` (string path, produced by `safety-core`'s `overlays.default`, unchanged by Task 1/2 — already used identically by `modules/home-manager/llm/opencode/default.nix:307`). Consumes `SAFETY_CORE_CONFIG_HOME` semantics from Task 1 (`src/config.ts`'s `defaultProfileConfigPath()`).
- Produces: `~/.config/opencode2/opencode/plugin/safety.ts` symlink; `"./plugin/safety.ts"` always present in OpenCode2's rendered `plugin` config list; the `opencode2` launcher script exports `SAFETY_CORE_CONFIG_HOME`.

- [ ] **Step 1: Modify `modules/home-manager/llm/opencode2/default.nix`**

Current content (55 lines) — full replacement:

```nix
{
  config,
  lib,
  pkgs,
  ...
}:
with lib; let
  cfg = config.modules.opencode2;
  jsonFormat = pkgs.formats.json {};
  safetyCore = pkgs.safety-core;
  # OpenCode2 still discovers a default config below XDG_CONFIG_HOME/opencode.
  # Give it a private XDG root and point OPENCODE_CONFIG at the flat file below,
  # so it cannot load OpenCode v1's configuration.
  configRoot = "${config.xdg.configHome}/opencode2";
  package = pkgs.writeShellScriptBin "opencode2" ''
    export SAFETY_CORE_CONFIG_HOME=${escapeShellArg config.xdg.configHome}
    export XDG_CONFIG_HOME=${escapeShellArg configRoot}
    export OPENCODE_CONFIG="$XDG_CONFIG_HOME/opencode.json"
    exec ${getExe pkgs.opencode2} "$@"
  '';
in {
  options.modules.opencode2 = {
    enable = mkEnableOption "experimental OpenCode2 AI coding assistant";

    settings = mkOption {
      type = jsonFormat.type;
      default = {};
      description = ''
        OpenCode2 configuration, written independently of OpenCode v1 to
        $XDG_CONFIG_HOME/opencode2/opencode.json.

        OpenCode2's configuration and plugin APIs are experimental. Keep
        settings here rather than adding V2-only keys to
        programs.opencode.settings, which is consumed by OpenCode v1.
      '';
    };
  };

  config = mkIf cfg.enable {
    home.packages = [package];

    xdg.configFile = {
      "opencode2/opencode.json".source = jsonFormat.generate "opencode2.json" (
        {
          "$schema" = "https://opencode.ai/config.json";
        }
        // cfg.settings
        // {
          plugin = (cfg.settings.plugin or []) ++ ["./plugin/safety.ts"];
        }
      );
      "opencode2/opencode/AGENTS.md".text =
        builtins.readFile ../agent-assets/common-instructions.md
        + "\n\n"
        + builtins.readFile ../agent-assets/rules/secrets-policy.md
        + "\n\n"
        + builtins.readFile ../agent-assets/rules/context7.md;
      "opencode2/opencode/plugin/safety.ts".source = safetyCore.opencodePluginFile;
    };
  };
}
```

Changes from the original, summarized: added `safetyCore = pkgs.safety-core;`; the `package` launcher now exports `SAFETY_CORE_CONFIG_HOME` (set to the real, unshadowed `config.xdg.configHome`) before overriding `XDG_CONFIG_HOME`; the generated `opencode2.json` always includes `"./plugin/safety.ts"` in its `plugin` list (appended to whatever the caller supplied via `cfg.settings.plugin`, defaulting to `[]`); and a new `xdg.configFile` entry symlinks `safetyCore.opencodePluginFile` to `opencode2/opencode/plugin/safety.ts`, matching the existing `opencode2/opencode/AGENTS.md` path convention (OpenCode2 discovers supplementary content under `$XDG_CONFIG_HOME/opencode/` regardless of where `OPENCODE_CONFIG` points).

- [ ] **Step 2: Verify the module evaluates cleanly**

`bankdata-wsl` is the only host with `modules.opencode2.enable = true;` today (`hosts/bankdata-wsl/home.nix:137`). Per this repo's `CLAUDE.md`, stage the change before any `nix` command can see it:

```bash
cd /home/user/projects/nixos-config
git add modules/home-manager/llm/opencode2/default.nix
nix eval .#nixosConfigurations.bankdata-wsl.config.system.build.toplevel.drvPath
```

Expected: prints a single `/nix/store/...-drv` path, with no "option does not exist" or eval errors. This forces full module evaluation (catching type/option errors) without building the OS closure.

- [ ] **Step 3: Manual smoke test (documented, not automatable from this repo)**

This step requires an actual deploy to `bankdata-wsl` and is **out of scope to run as part of this plan** — do not run `scripts/rebuild.sh` or switch the live system here. Record these steps for whoever next deploys to that host:

1. After deploying, run `opencode2` and confirm it starts without a plugin-load error (OpenCode logs a clear error if a listed plugin file fails to load).
2. Try reading a `*.pem` path from within OpenCode2 (e.g. ask it to `cat` one) and confirm it's blocked by the safety plugin (`tool.execute.before`'s `isSecretPath` check) — proves the plugin is actually wired in, not just present on disk.
3. Enable `programs.safetyCorePermissions.profiles.readOnlyBash.enable = true;` and `...ghApiReadOnly.enable = true;` on `bankdata-wsl`, redeploy, and confirm a read-only `gh api` call auto-allows inside OpenCode2 without a permission prompt — this is the specific case Task 1's `SAFETY_CORE_CONFIG_HOME` fix targets, worth confirming directly.

- [ ] **Step 4: Commit**

```bash
git add modules/home-manager/llm/opencode2/default.nix
git commit -m "opencode2: wire safety-core plugin and readOnlyBash profile"
```

---

## Self-Review Notes

- **Spec coverage:** "Change 1" (config.ts) → Task 1. "Change 2" (plugin reuse, no safety-core change) → reflected in Task 3's Step 1 (symlinks the existing, unmodified `opencodePluginFile`; no safety-core file touched for this part). "Change 3" (`nix/permissions.nix`) → Task 2. "Change 4" (nixos-config wiring) → Task 3. Testing section → each task's check steps (Tasks 1-2) and Task 3 Steps 2-3.
- **Placeholder scan:** no TBD/TODO; all code blocks are complete and were hand-verified against the real repos before writing (Task 1 and Task 2's checks were prototyped live with `nix build` / `nix eval` against real builds of `claudeCodeHooks` and a scratch copy of `nix/permissions.nix`; Task 3 follows the proven-working v1 pattern at `modules/home-manager/llm/opencode/default.nix:307` but was not independently built due to the full-OS-eval cost — flagged via its own eval-only verification step).
- **Type/name consistency:** `SAFETY_CORE_CONFIG_HOME` is spelled identically in Task 1 (`src/config.ts`) and Task 3 (`opencode2/default.nix`'s launcher). `defaultProfileConfigPath()` signature is unchanged. `readOnlyBashCommands` / `modules.opencode2.settings.permission.bash` naming in Task 2 matches the sibling `programs.opencode.settings.permission.bash` line immediately above it.
