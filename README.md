# `safety-core`

`safety-core` is an agent-steering tool that helps reduce permission prompts for the human operator.

The goal is to identify safe, read-only commands and automatically approve a Bash tool call only when enabled policies prove every reachable modeled execution safe. It also features explicit blocking to prevent access to sensitive files and data, and to steer the agent toward safer tools.

`safety-core` is not meant to be a strong security boundary. If you need security guarantees, use mechanisms such as sandboxing and least-privilege credentials.

## How is `safety-core` different?

Unlike prefix- or regex-based matching, `safety-core` parses Bash and performs a bounded, stateful symbolic analysis of the commands that may execute. It tracks shell state, known and unknown values, branches, functions, wrappers, and nested invocations without executing them. A command is automatically approved only when the enabled policies can prove every reachable modeled execution safe; uncertain or unsupported behavior is deferred or blocked.

Prefix- and regex-based solutions often become brittle when dealing with argument ordering. For example, `kubectl` accepts the `-n <namespace>` argument in multiple positions, and the selected namespace can materially affect an approval or denial decision.

## Install and configure

The authoritative global configuration is JSON at
`$SAFETY_CORE_CONFIG_HOME/safety-core/config.json`, or
`$XDG_CONFIG_HOME/safety-core/config.json`, or
`$HOME/.config/safety-core/config.json`. The selected environment variable must
be an absolute path. `safety-core validate` prints the canonical source path and
SHA-256 digest selected for the current directory; use it before enabling a
policy. `safety-core explain --json -- '<command>'` reports the exact modeled
events and decisions for local diagnosis.

```json
{
  "version": 1,
  "policies": ["/absolute/path/read-only.policy.json"],
  "projectPolicies": { "mode": "disabled" },
  "bashAnalysis": {
    "maxFunctionDepth": 128,
    "maxNestedScriptDepth": 64,
    "maxSteps": 7500,
    "maxWorkItems": 10000
  },
  "pi": {
    "autoApprove": false
  }
}
```

Global sources may be trusted frozen `.policy.mjs` code or declarative
`.policy.json` files. Project sources are declarative `.policy.json` only. Use
`projectPolicies.mode: "all"` only when each discovered project policy is
trusted; `"allowlisted"` requires canonical absolute roots in `allowedRoots`.
Project permissions can expand global permission coverage, but a global guard
denial remains dominant.

The Home Manager module exposes these same fields at
`programs.safetyCorePermissions`, plus `completePolicySources`, `prCreate`,
`installCli`, and `installClaudeBashHook`, plus Pi's `autoApprove` and
`judgeModel` settings. `completePolicySources` references
the packaged complete DSL source set; `prCreate` renders a complete,
repository/organization-scoped `gh pr create` DSL source. The flake packages
the CLI, core/parser assets, DSL source directory, and Claude, OpenCode v1,
OpenCode v2, and Pi adapter artifacts. OpenCode v1 and v2 use separate
packaged plugin files so either plugin API can evolve without changing the
other adapter.

OpenCode and Pi load one runtime when their plugin/extension starts. Their
human-controlled TUI actions can replace that runtime with the latest valid
policies from disk without restarting: select `Reload policies from disk` in
Pi's `/safety-core` settings, or install OpenCode's separate
`opencodeTuiPluginFile` companion and select `Reload safety policies`. Neither
action is registered as an agent tool; a failed reload retains the active
policy runtime. Claude hooks are separate processes: SessionStart state records the selected root, canonical
configuration/source paths, and SHA-256 digests under the session ID. Later
hooks verify those exact bytes before loading; any changed or missing source,
or a runtime policy exception, hard-fails the session until it is restarted.

Pi exposes `/safety-core` in TUI mode. Its `Auto-approve deferred commands`
setting skips only the one-time confirmation for policy `defer` outcomes; it
never bypasses deterministic policy denials, startup/evaluation failures,
secret-path blocks, or a judge denial. The setting and the selected judge model
follow the active Pi session branch. Global Pi defaults come from the `pi`
configuration above (or the matching Home Manager options).

See [policy authoring](./docs/policy-authoring.md),
[read-only profiles](./docs/read-only-command-profiles.md), and
[executable identity limitations](./docs/executable-identity-limitations.md).
