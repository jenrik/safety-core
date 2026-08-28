# OpenCode2 integration design

## Context

`nixos-config` ships `opencode2`, an experimental build of `anomalyco/opencode`'s
`dev` branch, alongside the stable `opencode` v1. OpenCode2 runs with a
private, isolated configuration root (`~/.config/opencode2`, via
`XDG_CONFIG_HOME` override in its launcher script) so it can't read or clobber
v1's configuration.

Today `safety-core`'s OpenCode plugin (`adapters/opencode.ts`) and the
`readOnlyBash` / `ghApiReadOnly` permission profiles (`nix/permissions.nix`)
are wired only into OpenCode v1 via `nixos-config`'s
`modules/home-manager/llm/opencode/default.nix`. OpenCode2's module
(`modules/home-manager/llm/opencode2/default.nix`) currently has no plugin
wiring at all.

This spec covers extending both the safety plugin and the `readOnlyBash`
profile to OpenCode2, plus a config-resolution fix required to make the
`ghApiReadOnly` profile actually take effect there.

## Problem: profile config resolution under an isolated `XDG_CONFIG_HOME`

`src/config.ts`'s `defaultProfileConfigPath()` resolves the shared
`safety-core/profiles.json` (which every harness adapter reads via
`isProfileEnabled()`) relative to `process.env.XDG_CONFIG_HOME`, falling back
to `~/.config`.

`nix/permissions.nix` writes this file unconditionally to the *real*
`~/.config/safety-core/profiles.json` via `xdg.configFile`. OpenCode v1, pi,
and claude-code all see this correctly, since none of them override
`XDG_CONFIG_HOME`.

OpenCode2's launcher, however, sets `XDG_CONFIG_HOME=~/.config/opencode2` for
its own isolation. Under that override, `defaultProfileConfigPath()` would
resolve to `~/.config/opencode2/safety-core/profiles.json`, which never
exists. `loadProfileConfig()` fails closed (returns `{}`), so `ghApiReadOnly`
would silently read as disabled inside OpenCode2 even when the user has it
enabled — a functional bug, not a security hole, but the profile would be
inert for that harness.

### Fix

Add a new override environment variable, `SAFETY_CORE_CONFIG_HOME`, checked
before `XDG_CONFIG_HOME`:

```ts
const base =
  process.env.SAFETY_CORE_CONFIG_HOME ??
  process.env.XDG_CONFIG_HOME ??
  join(process.env.HOME ?? "", ".config");
```

`XDG_CONFIG_HOME` continues to work as today for every harness that doesn't
touch it. OpenCode2's launcher additionally exports
`SAFETY_CORE_CONFIG_HOME` pointing at the real, unshadowed config home
(`config.xdg.configHome`, a Nix-evaluated literal — not a runtime shell
capture), so safety-core's own shared state stays resolvable regardless of
what an individual harness does with `XDG_CONFIG_HOME` for its own purposes.

`defaultAuditPath()` in `src/audit.ts` is unaffected: it's keyed by
`XDG_STATE_HOME`, which OpenCode2's launcher doesn't override, and audit
paths are already namespaced per-harness (`defaultAuditPath("opencode2")`
would resolve under the real `~/.local/state/opencode2/`).

## Change 1: `src/config.ts`

Add the `SAFETY_CORE_CONFIG_HOME` override to `defaultProfileConfigPath()`
as shown above. No other source changes in `src/`.

## Change 2: OpenCode plugin reuse (no safety-core change)

`adapters/opencode.ts` and its packaged output (`package.nix`'s
`opencodePluginFile`) are reused as-is for OpenCode2. The adapter's only
reference to OpenCode's plugin API is a type-only import of
`@opencode-ai/plugin` (erased at load time — there's no runtime npm
dependency on that package), and OpenCode2 is built from the same
`anomalyco/opencode` monorepo, exposing the same plugin hooks
(`tool.execute.before`, `permission.ask`, `tool.execute.after`). No second
build or forked adapter file is needed; `nixos-config` symlinks the same
`pkgs.safety-core.opencodePluginFile` into both v1's and OpenCode2's plugin
directories.

If OpenCode2's plugin API diverges from v1's in the future, that's a
fork-then decision, not a fork-now one.

## Change 3: `nix/permissions.nix` — `readOnlyBash` for OpenCode2

Extend the existing `mkIf cfg.profiles.readOnlyBash.enable` block with a
third target, alongside the current `programs.claude-code` and
`programs.opencode` entries:

```nix
config.modules.opencode2.settings.permission.bash =
  listToAttrs (map (cmd: nameValuePair "${cmd} *" "allow") readOnlyBashCommands);
```

This reuses the single existing `programs.safetyCorePermissions.profiles.readOnlyBash.enable`
toggle — no new option is introduced. `ghApiReadOnly` needs no equivalent
static wiring here: it's handled entirely inside the already-wired plugin's
`permission.ask` handler via `isProfileEnabled()`, same as v1.

This couples safety-core's home-manager module to `modules.opencode2`, a
private option defined only in `nixos-config`, not a generic external
module (unlike `programs.opencode` / `programs.claude-code`, which come from
well-known upstream home-manager modules). That's acceptable only because
`nixos-config` is safety-core's sole consumer today
(`safety-core.url = "git+ssh://git@forgejo.jener.dk/jenrik/safety-core"` in
its `flake.nix`); a comment in `nix/permissions.nix` should note this
assumption so it's revisited if safety-core ever gains another consumer.

## Change 4 (in `nixos-config`, not this repo): OpenCode2 module wiring

`modules/home-manager/llm/opencode2/default.nix` needs:

- `safetyCore = pkgs.safety-core;` (mirroring v1's `default.nix`).
- `xdg.configFile."opencode2/opencode/plugin/safety.ts".source = safetyCore.opencodePluginFile;`
  — following the existing `"opencode2/opencode/AGENTS.md"` path convention;
  OpenCode2 still discovers supplementary content under
  `$XDG_CONFIG_HOME/opencode/` even though its main config file is
  redirected via `OPENCODE_CONFIG`.
- The rendered `settings.plugin` array always includes `"./plugin/safety.ts"`,
  computed as `(cfg.settings.plugin or []) ++ ["./plugin/safety.ts"]` rather
  than a plain `//` merge, so a caller-supplied `cfg.settings.plugin` can't
  silently drop it.
- The `package = pkgs.writeShellScriptBin "opencode2" ...` launcher additionally
  exports `SAFETY_CORE_CONFIG_HOME=${escapeShellArg config.xdg.configHome}`
  alongside its existing `XDG_CONFIG_HOME` override.

No changes are anticipated to `overlays/opencode2.nix` or
`pkgs/opencode2/default.nix` (binary build, unrelated to this work).

## Testing / verification

**safety-core**: add a runtime check to `flake.nix`'s `checks`, alongside
the existing `hooks-runtime` / `gh-api-hook-runtime` checks (a
`pkgs.runCommand` invoking `node -e` directly — this repo has no unit-test
framework; `checks.*` is the existing correctness-verification convention).
It exercises `defaultProfileConfigPath()`'s precedence:

1. `SAFETY_CORE_CONFIG_HOME` set (with a `profiles.json` there) → resolves
   to that path, regardless of `XDG_CONFIG_HOME`. Simulates OpenCode2.
2. `SAFETY_CORE_CONFIG_HOME` unset, `XDG_CONFIG_HOME` set → falls back
   correctly (today's behavior, unchanged).
3. Both unset → falls back to `~/.config` via `HOME`.

**nixos-config**: no unit-test framework applies to module wiring itself.
Verification is:

- A `home-manager build` (or this repo's existing build check) succeeds
  with `modules.opencode2.enable = true` and
  `programs.safetyCorePermissions.profiles.readOnlyBash.enable = true`,
  confirming the module evaluates and
  `~/.config/opencode2/opencode/plugin/safety.ts` gets symlinked.
- Manual smoke test: launch `opencode2`, confirm the safety plugin loads
  without error, and exercise one blocked case (e.g. reading a `*.pem`
  path) to confirm `tool.execute.before` fires.
- Manual check that `ghApiReadOnly`, once toggled on, actually takes effect
  inside OpenCode2 — the specific case the `SAFETY_CORE_CONFIG_HOME` fix
  targets, worth confirming directly rather than trusting the nix check
  alone.
