# `bun-run` project policy scope

## Intent

Automatically authorize the explicit `bun run <script>` spellings that execute
this project's reviewed build and test scripts, so an agent working in this
repository is not prompted for the documented development loop
(`bun run build:native-packages`, `bun run test`, `bun run typescheck`).

## Protected action and asset

The protected action is automatic authorization of one modeled `bun`
invocation that will execute a script defined in this project's
`package.json`. The asset behind the decision is code execution authority on
the operator's machine through that script: the policy decides *which
invocations* are authorized automatically and claims nothing about what the
script then does.

This policy is a spelling allowlist over trusted project scripts. The DCRM
language cannot read `package.json`, so the allowlist cannot prove that a
script of that name exists or that its body is unchanged. The script body, and
everything it spawns (shells, bundlers, network access, file writes), execute
with the agent's full ambient authority.

## Tested version and in-scope grammar

The inventory is pinned to the installed and tested `bun 1.3.13`. Exactly this
grammar is permitted:

```text
bun run SCRIPTS
```

where:

- the immediate, unqualified executable spelling is exactly `bun`
  (`isDirectExecutable("bun")`);
- immediate lookup resolves the invocation to `external-path`; a
  `shell-function`, builtin, or unresolved target defers;
- there are no command-prefix assignments;
- the first operand word is exactly `run` (case-sensitive);
- the second operand word is exactly one member of the reviewed allowlist
  `build:native-packages`, `test`, `typescheck` (case-sensitive);
- there is no third word: argv ends immediately after the script name.

`bun run build:native-packages`, `bun run test`, and `bun run typescheck` are
the complete in-scope set. The allow is emitted only at end of argv, so no
unchecked suffix can be accepted.

## Out of scope and threat-model exclusions

Every form below returns `defer`, leaving the native harness prompt in place.
The list gives the reason each form is deliberately excluded.

- **Any other script name**, including a script later added to
  `package.json`. A new script is unreviewed until a human extends the
  allowlist in `.safety-core/bun-run.policy.json`; the policy is not a
  "run anything in package.json" grant.
- **The implicit `bun <script>` spelling** (`bun typescheck`). At this layer
  the implicit spelling is lexically indistinguishable from Bun's builtin
  subcommand spellings, so permitting it for the allowlisted name `test` would
  also permit `bun test <pattern>` through this policy and silently widen
  `bun-test`'s project-relative selection rule. Only the explicit `run`
  subcommand is modeled.
- **Any flag, before or after the subcommand** (`bun run --silent test`,
  `bun --smol run test`, `bun run -b test`). No option is declared. Notably
  `-b`/`--bun` is excluded because it symlinks `node` to Bun and therefore
  changes the runtime a Node-targeted script uses; `--watch`/`--hot` never
  terminate; `-r`/`--preload`, `--require`, and `--import` load a module that
  this policy has not reviewed.
- **Any word after the script name** (`bun run test tests/example.test.ts`,
  `bun run build:native-packages --outdir=/tmp`). Bun appends those words to
  the script command, so for `test` (whose body is
  `bun run build:native-packages && bun test`) they can reach the inner
  `bun test` and would bypass `bun-test`'s project-relative path rule. No
  pass-through argument form is authorized.
- **Bare `bun run` and `bun run --help`**, which list scripts rather than run
  one; script listing is not part of this policy's protected action.
- **Running a file** (`bun run ./scripts/build-native-node-packages.ts`,
  `bun run scripts/build-bash-grammar.ts`). File execution is a different
  authorized action from the reviewed script allowlist.
- **Path-qualified spellings** (`/usr/bin/bun run test`, `./bun run test`),
  which are not the immediate unqualified executable spelling.
- **Bash function shadowing**, locally defined or inherited
  (`BASH_FUNC_bun%%`), which defers rather than authorizing a function body.
- **`command bun run test` and other wrappers.** The core models `command` as
  its own invocation first and the nested `bun` child second. This policy
  selects and permits the child; the outer `command` builtin needs its own
  policy, so a configuration containing only the project bun policies leaves
  the complete source deferred.
- **Redirections, pipelines, and shell constructs** around the invocation. File
  opens remain independently subject to harness file permission checks, and
  every other modeled command keeps its own decision.

This policy does not defend against adversarial bypasses and does not model
`cd`, environment mutation, or script bodies. Making the same thing happen
through another interpreter, or editing the policy file, is outside the
documented non-adversarial threat model.

## Assumptions and non-goals

The policy assumes the operator has reviewed the three `package.json` script
definitions and accepts that they are trusted project code with arbitrary
effects. It assumes Bash resolution facts supplied by the analyzer
(immediate target, executable spelling, prefix assignments, operand
resolution) are complete; incomplete values defer.

It is not a sandbox, not a dependency, network, or filesystem policy, not an
argument validator for the scripts, and not a proof that the named script
exists or is unmodified. It does not authorize the same work through
`bash -c`, `bunx`, `node`, or any other runner.

These policy bytes live inside the repository the agent works in (a project
policy under `.safety-core/`). Under the documented non-adversarial threat
model that is acceptable, but it means an agent edit to this file changes its
own authorization for the next harness session; OpenCode and Pi retain the
policy object loaded at start-up until the harness is restarted or policies are
reloaded.

## Expected outcomes

- **permit:** each in-scope invocation returns `allow`. The complete request is
  automatically allowed only when every other modeled invocation and every
  harness file check also allows, and no guard denies.
- **defer:** every form outside the grammar returns `defer`, including prefix
  assignments, other script names, flags, trailing words, the implicit alias,
  path-qualified spellings, and function shadowing. A harness prompt or unknown
  file-permission result for a redirected path also remains deferred at request
  finalization.
- **deny:** this policy has no deny rule. Independent guard policies and harness
  file checks can still deny the request, and that denial dominates.

The v1 DCRM grammar only permits `reason` and `suggestion` templates on
`allow` and `deny` terminals, so the per-exclusion reasons above are recorded
here and in the policy's state structure rather than being rendered for a
`defer` outcome.
