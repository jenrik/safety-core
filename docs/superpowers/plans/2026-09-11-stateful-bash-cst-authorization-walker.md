# Stateful Bash CST Authorization Walker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace flattened Bash-command authorization with a pure, bounded, stateful CST walker that resolves safe static execution and dispatches every command through a dedicated handler.

**Architecture:** A `tree-sitter-bash` adapter projects the CST into a backend-neutral Bash program model. An iterative runner threads persistent environment frames, deltas, checkpoints, budgets, and outcomes through a pure walker; handlers normalize their own command syntax and recursively dispatch nested execution. Existing policy entry points become thin compatibility wrappers around the walker until their flattened parsing paths are removed.

**Tech Stack:** TypeScript ESM, `web-tree-sitter`, `tree-sitter-bash`, Bun tests, Nix flake checks, Home Manager Nix module.

**Spec:** `docs/superpowers/specs/2026-09-11-stateful-bash-cst-authorization-walker-design.md`

## Global Constraints

- Preserve the hard-block precedence of secret and explicit command policies.
- Allow only when every reachable execution is proven safe; return neutral for unresolved execution and ordinary analysis failures.
- Stop immediately on a proven deny, but continue after indeterminate or failure evidence so a later deny is found.
- Keep all walker, environment, parser projection, dispatcher, and handler functions pure; never mutate inputs.
- Use an iterative runner; do not rely on JavaScript tail-call optimization.
- Do not let the walker read `process.env`; adapters pass either a verified environment snapshot or an explicitly unavailable environment.
- Never include inherited or resolved values in diagnostics, audit records, trace snapshots, or assertion failures.
- Expose all user-adjustable analysis limits as Nix Home Manager options rendered into `profiles.json`.
- Start performance calibration with function depth 128, nested-script depth 64, total steps 100,000, and work items 10,000; adjust final defaults only after cap-exhaustion measurement targets roughly 1,000 ms.
- Add unit tests and deterministic property tests for every behavior change, plus the isolated real-Bash equivalence suite described below.
- Run an adversarial review by a frontier-model reviewer before completion; resolve every Critical or Important finding.
- Do not stage, commit, amend, push, or open a pull request unless the human explicitly authorizes it.

---

## File structure

| Path | Responsibility |
| --- | --- |
| `src/bash/cst.ts` | Backend-neutral projected Bash program, statement, word, redirect, and source-span types. |
| `src/bash/environment.ts` | Immutable persistent frames, binding deltas, command overlays, checkpoints, branch joins, and taint. |
| `src/bash/expand.ts` | Pure static word and assignment expansion against an environment snapshot. |
| `src/bash/outcome.ts` | `safe`/`indeterminate`/`failure`/`deny` accumulation and final verdict conversion. |
| `src/bash/runner.ts` | Iterative `continue`/`fork`/`result` work agenda and budget enforcement. |
| `src/bash/walker.ts` | Bash statement traversal, function frames, groups, subshells, lists, and branch state merging. |
| `src/bash/dispatch.ts` | Normalized invocation cursor, handler registry, and pure command dispatch. |
| `src/bash/handlers/*.ts` | Dedicated handlers for shell builtins, transparent wrappers, `sh`, `gh`, HTTP tools, secret readers, kubectl, and read-only CLIs. |
| `src/bash/policies/*.ts` | Small invocation-level policy functions, separated from shell and command grammar. |
| `src/shell.ts` | Parser initialization plus projection from `web-tree-sitter` into `src/bash/cst.ts`; retains `parseBash()` temporarily. |
| `src/authorization.ts` | Public walker-backed authorization API and compatibility adapters for existing policy exports. |
| `src/config.ts`, `nix/permissions.nix` | Validated analysis-limit config and Home Manager rendering. |
| `adapters/*.ts`, `adapters/claude-code/*.ts` | Harness-specific initial-environment capability and verdict-to-harness mapping. |
| `tests/bash-*.test.ts` | Core unit/property, dispatch, migration, equivalence, and performance calibration coverage. |

## Task 1: Project the Bash CST into a backend-neutral program model

**Files:**
- Create: `src/bash/cst.ts`
- Modify: `src/shell.ts:96-256`
- Modify: `src/index.ts:6-14`
- Create: `tests/bash-cst.test.ts`

**Interfaces:**
- Consumes: initialized `web-tree-sitter` parser in `src/shell.ts`.
- Produces: `parseBashProgram(source): BashProgram | BashParseFailure` and projected node types consumed by every later walker task.

- [ ] **Step 1: Write projection tests before adding the projection API**

  Add cases for ordered assignment prefixes, redirect targets, functions, lists, subshells, brace groups, pipelines, `if`, and unsupported syntax. Assert source spans and word kinds rather than raw `web-tree-sitter` nodes:

  ```ts
  expect(program.statements[0]).toMatchObject({
    kind: "command",
    assignments: [{ name: "F" }, { name: "D" }],
    words: [{ kind: "word" }, { kind: "word" }, { kind: "word" }],
  });
  expect(program.statements[0].span).toEqual({ start: 0, end: source.length });
  ```

- [ ] **Step 2: Run the new CST test and confirm the missing API failure**

  Run: `bun test tests/bash-cst.test.ts`

  Expected: FAIL because `parseBashProgram` and the projected program types do not exist.

- [ ] **Step 3: Define the normalized syntax model and parser projection**

  Add these discriminated types in `src/bash/cst.ts`:

  ```ts
  export interface SourceSpan { readonly start: number; readonly end: number }
  export type BashStatement = BashCommand | BashFunction | BashList | BashPipeline | BashSubshell | BashGroup | BashIf | BashUnsupported;
  export interface BashProgram { readonly source: string; readonly statements: readonly BashStatement[] }
  export interface BashCommand { readonly kind: "command"; readonly assignments: readonly BashAssignment[]; readonly words: readonly BashWord[]; readonly redirects: readonly BashRedirect[]; readonly span: SourceSpan }
  export interface BashUnsupported { readonly kind: "unsupported"; readonly reason: string; readonly span: SourceSpan }
  ```

  In `src/shell.ts`, add `parseBashProgram()` that returns `BashParseFailure` when the parser is unavailable or CST error nodes affect a policy-relevant region. Project only immutable plain objects. Reimplement the existing `parseBash()` as a compatibility flattening projection from `BashProgram`, preserving its current `SimpleCommand` output for callers not migrated yet.

- [ ] **Step 4: Export and verify parser compatibility**

  Export `parseBashProgram` and projected CST types from `src/index.ts`. Extend the test with existing `parseBash("A=1 echo x")` assertions to prove callers retain the current flattened output while the new program model preserves assignments.

  Run: `bun test tests/bash-cst.test.ts tests/gh-pr-create.test.ts tests/read-only-cli.test.ts`

  Expected: PASS.

- [ ] **Step 5: Review the projection boundary**

  Confirm `src/bash/cst.ts` imports no `web-tree-sitter` type and no result exposes a live parser node. Confirm unsupported source nodes have source provenance and cannot silently disappear.

## Task 2: Implement persistent frames, deltas, checkpoints, and taint

**Files:**
- Create: `src/bash/environment.ts`
- Create: `tests/bash-environment.test.ts`

**Interfaces:**
- Consumes: `SourceSpan` from `src/bash/cst.ts`.
- Produces: immutable `Environment`, `Binding`, `EnvironmentPatch`, `BranchCheckpoint`, lookup, assignment, scope, overlay, fork, merge, and taint operations for the expander and walker.

- [ ] **Step 1: Write failing lifetime, persistence, and merge tests**

  Cover known lookup, unknown lookup, `Unset`, export/readonly attributes, parent lookup, function-local shadowing, command-overlay discard, branch agreement, branch disagreement, branch write-set-only merging, and arbitrary-mutation taint:

  ```ts
  const base = fromInitialEnvironment({ F: "BAR" });
  const overlay = beginCommandOverlay(base);
  const withD = assignBinding(overlay, "D", known("GAR"));
  expect(lookupBinding(withD, "F").value).toEqual(known("BAR"));
  expect(lookupBinding(endCommandOverlay(withD), "D").value).toEqual(unset());
  ```

- [ ] **Step 2: Run the environment tests and confirm failure**

  Run: `bun test tests/bash-environment.test.ts`

  Expected: FAIL because environment constructors and operations do not exist.

- [ ] **Step 3: Implement immutable environment operations**

  Define:

  ```ts
  export type BindingValue = { kind: "known"; value: string } | { kind: "unknown"; reason: UnknownReason } | { kind: "unset" };
  export interface Binding { readonly value: BindingValue; readonly exported: boolean; readonly readonly: boolean }
  export interface Environment { readonly frame: Frame; readonly overlay?: Frame; readonly budgets: Budgets }
  export interface BranchCheckpoint { readonly base: Environment; readonly writes: ReadonlySet<string> }
  ```

  Represent a frame as parent pointer plus immutable base binding store and a bounded delta chain. Implement `assignBinding`, `unsetBinding`, `setExported`, `pushFunctionFrame`, `pushSubshellFrame`, `beginCommandOverlay`, `endCommandOverlay`, `forkCheckpoint`, `recordWrite`, `mergeCheckpoint`, and `taintFrame`. `mergeCheckpoint` must inspect only changed keys plus frame-level taint, not copy all inherited bindings.

- [ ] **Step 4: Add deterministic property tests**

  Use a seeded linear-congruential generator, as existing tests do, to generate binding names and values. Assert that inputs are unchanged, assignments only change the target frame, a non-written unknown binding never becomes known, deterministic overwrite may replace unknown with known, and a branch merge marks disagreements unknown.

  Run: `bun test tests/bash-environment.test.ts`

  Expected: PASS.

- [ ] **Step 5: Check representation invariants**

  Add assertions in tests that a command overlay shares the parent frame identity, a fork shares its checkpoint frame identity, and a branch delta contains only written names. Do not assert private map implementation details beyond those sharing guarantees.

## Task 3: Add static word expansion and command normalization

**Files:**
- Create: `src/bash/expand.ts`
- Create: `tests/bash-expand.test.ts`

**Interfaces:**
- Consumes: `BashWord`, `BashAssignment`, and `BashCommand`; `Environment` lookup and overlay operations.
- Produces: `ResolvedWord`, `NormalizedCommand`, and assignment-prefix patches consumed by `src/bash/dispatch.ts`.

- [ ] **Step 1: Write failing expansion tests**

  Include the agreed ordering case and unresolved dynamic forms:

  ```ts
  expect(normalizeCommand(command("F=BAR D=GAR echo $D $F"), emptyEnvironment())).toMatchObject({
    executable: { kind: "known", value: "echo" },
    argv: [{ kind: "known", value: "GAR" }, { kind: "known", value: "BAR" }],
  });
  expect(expandWord(word("$COMMAND"), unknownEnvironment("COMMAND"))).toMatchObject({ kind: "unknown" });
  expect(expandWord(word("$(id)"), emptyEnvironment())).toMatchObject({ kind: "unknown" });
  ```

- [ ] **Step 2: Run the expansion test and confirm failure**

  Run: `bun test tests/bash-expand.test.ts`

  Expected: FAIL because normalization and word-expansion functions do not exist.

- [ ] **Step 3: Implement supported expansion without executing shell code**

  Implement `expandWord(word, environment)` and `normalizeCommand(command, environment)`. Expand literal concatenation and direct `$NAME`/`${NAME}` references only when every referenced binding is known. Mark command substitution, process substitution, indirect expansion, globbing, array expansion, arithmetic expansion, and unsupported parameter operators unknown with redacted reasons. Apply assignment prefixes left-to-right to a command overlay before expanding subsequent assignments, executable, arguments, and redirects.

- [ ] **Step 4: Prove lifetime and provenance behavior**

  Add tests that prefix assignments alter only `NormalizedCommand.environment`, standalone assignment commands return a persistent patch, and every unknown result retains the CST source span and variable name but not a resolved value.

  Run: `bun test tests/bash-expand.test.ts tests/bash-environment.test.ts`

  Expected: PASS.

- [ ] **Step 5: Add expansion properties**

  Generate ordered chains of literal assignments and direct references. Compare their normalized known argv against a simple test-local left-to-right model. Generate a chain with at least one unknown dependency and assert no dependent expansion returns a known value until a later literal assignment overwrites that name.

## Task 4: Implement outcomes, budgets, and the iterative work runner

**Files:**
- Create: `src/bash/outcome.ts`
- Create: `src/bash/runner.ts`
- Create: `tests/bash-runner.test.ts`

**Interfaces:**
- Consumes: `Environment` and `SourceSpan`.
- Produces: `Outcome`, `AuthorizationVerdict`, `Step`, `BashAnalysisLimits`, and `runSteps()` for walker and handlers.

- [ ] **Step 1: Write failing outcome and termination tests**

  Test that deny stops later targets, failure/indeterminate do not stop later targets, all-safe ends allow, and any sticky uncertainty ends neutral. Include a self-requeueing continuation that reaches a function-depth or step limit without overflowing the JavaScript stack.

  ```ts
  expect(finalize([safe(), indeterminate(span)]) .kind).toBe("neutral");
  expect(runSteps(repeatingContinue, limits({ maxSteps: 3 })).outcome.kind).toBe("failure");
  ```

- [ ] **Step 2: Run the runner tests and confirm failure**

  Run: `bun test tests/bash-runner.test.ts`

  Expected: FAIL because runner types and outcome combinators do not exist.

- [ ] **Step 3: Implement the monotonic outcome lattice and agenda**

  Define `safe`, `indeterminate`, `failure`, and `deny` evidence. Define `Step` as the `continue`/`fork`/`result` union from the spec. Use a loop and explicit agenda in `runSteps`; never recursively execute a successor. Preserve indeterminate/failure evidence while dequeuing later work, return immediately when deny is observed, and convert complete evidence to `allow`, `neutral`, or `deny` at the end.

- [ ] **Step 4: Enforce every structural budget**

  Consume and test `maxFunctionDepth`, `maxNestedScriptDepth`, `maxSteps`, and `maxWorkItems`. Return redacted `analysis-failure` evidence that identifies the exceeded budget and source span. A budget failure must be neutral at finalization unless a deny has already been found.

  Run: `bun test tests/bash-runner.test.ts`

  Expected: PASS.

- [ ] **Step 5: Add stack-safety property coverage**

  Generate at least 2,500 sequential `continue` steps and assert completion without `RangeError`. Generate a nested fork workload bounded by `maxWorkItems` and assert the runner returns failure rather than allocating unbounded work.

## Task 5: Walk Bash statements, functions, scopes, and control flow

**Files:**
- Create: `src/bash/walker.ts`
- Create: `src/bash/handlers/builtins.ts`
- Create: `tests/bash-walker.test.ts`

**Interfaces:**
- Consumes: projected `BashProgram`, `Environment`, `normalizeCommand`, `Step`, and a dispatcher callback.
- Produces: `walkProgram(program, context): Step`, modeled function registry, and shell-builtin transitions.

- [ ] **Step 1: Write failing semantic-walk tests**

  Cover standalone assignment persistence, prefix overlay discard, dynamic function lookup, `local`, `export`, `readonly`, `unset`, brace-group persistence, subshell isolation, branch merge, unsupported mutation taint, recursion cap, and distinct environments for repeated function calls.

  ```ts
  const result = analyze(`X=outer; f(){ local X=inner; echo "$X"; }; f; echo "$X"`);
  expect(result.invocations.map((call) => call.argv)).toEqual([["inner"], ["outer"]]);
  ```

- [ ] **Step 2: Run the walker tests and confirm failure**

  Run: `bun test tests/bash-walker.test.ts`

  Expected: FAIL because no statement walker exists.

- [ ] **Step 3: Implement the pure statement walker**

  Implement statement dispatch for commands, function declarations/calls, sequential lists, `&&`/`||`, `if`, brace groups, subshells, and pipelines. Model unknown command status by exploring every reachable continuation and merging at the join. For functions, push a dynamic call frame, bind arguments, apply a temporary prefix overlay, consume function depth, and return to the saved caller continuation. For a subshell or pipeline child, use a copied environment whose writes never update the parent.

- [ ] **Step 4: Implement modeled builtins and conservative unsupported behavior**

  Implement dedicated pure handlers for assignment-only commands, `local`, `export`, `readonly`, `unset`, and `return`. For `read NAME`, taint only `NAME`; for unknown `eval`, `source`, loop mutation, or unknown shell interpreter payload, emit indeterminate evidence and taint the affected frame/default lookup while continuing the enclosing walk.

  Run: `bun test tests/bash-walker.test.ts tests/bash-runner.test.ts tests/bash-expand.test.ts`

  Expected: PASS.

- [ ] **Step 5: Add function-isolation properties**

  Generate two calls of one function with different known caller bindings. Assert each invocation observes its own caller value, no local binding leaks, and recursive calls fail by budget rather than stack overflow.

## Task 6: Introduce dedicated command dispatch and nested-execution handlers

**Files:**
- Create: `src/bash/dispatch.ts`
- Create: `src/bash/handlers/unknown.ts`
- Create: `src/bash/handlers/wrappers.ts`
- Create: `src/bash/handlers/sh.ts`
- Create: `tests/bash-dispatch.test.ts`

**Interfaces:**
- Consumes: `NormalizedCommand`, walker callback, `Step`, and outcome evidence.
- Produces: `CommandHandler`, `InvocationCursor`, `CommandRegistry`, `dispatchCommand()`, and handlers for `env`, `command`, `exec`, `nice`, `nohup`, `setsid`, `stdbuf`, `timeout`, `strace`, `xargs`, `find -exec`, and `sh -c`.

- [ ] **Step 1: Write failing handler-routing tests**

  Verify each registered executable reaches only its own handler, handlers receive immutable cursors, recognized flags can be consumed in supported positions, and unregistered executables reach `unknown-command`.

  ```ts
  expect(analyze("strace -f gh pr create --repo github.com/acme/widgets").invocations[0])
    .toMatchObject({ executable: "gh", argv: ["pr", "create", "--repo", "github.com/acme/widgets"] });
  expect(analyze("sh -c '$COMMAND'", { COMMAND: unknown("ambient") }).kind).toBe("neutral");
  ```

- [ ] **Step 2: Run the dispatch test and confirm failure**

  Run: `bun test tests/bash-dispatch.test.ts`

  Expected: FAIL because dispatch types and handlers do not exist.

- [ ] **Step 3: Implement cursor and registry contracts**

  Define:

  ```ts
  export interface InvocationCursor { readonly invocation: NormalizedCommand; readonly index: number; readonly options: Readonly<Record<string, unknown>> }
  export interface CommandHandler { readonly name: string; handle(cursor: InvocationCursor, context: DispatchContext): Step }
  export interface CommandRegistry { resolve(executable: string): CommandHandler }
  ```

  `dispatchCommand()` resolves one named handler, provides an immutable cursor, and records a redacted invocation observation. Handlers return a continuation or outcome; no handler mutates a cursor, options object, environment, or registry.

- [ ] **Step 4: Implement nested execution conservatively**

  Implement wrapper-specific option consumption and child boundaries. `env`, `command`, `exec`, `nice`, `nohup`, `setsid`, `stdbuf`, `timeout`, and `strace` dispatch a known child only after their own grammar determines it. `sh -c` parses and walks only a known script word. `xargs` and `find -exec` dispatch a child only if executable and all security-relevant operands are statically known; otherwise they emit indeterminate child-execution evidence. Unknown commands emit indeterminate evidence through the dedicated fallback handler.

  Run: `bun test tests/bash-dispatch.test.ts tests/bash-walker.test.ts`

  Expected: PASS.

- [ ] **Step 5: Add flag-order and nested-dispatch properties**

  Generate permutations of audited wrapper flags around a fixed known child and assert identical child invocation. Generate an unknown child word at every argument boundary and assert the result is neutral, never allow.

## Task 7: Migrate secret-read, GitHub HTTP, and kubectl policy to invocation policies

**Files:**
- Create: `src/bash/handlers/readers.ts`
- Create: `src/bash/handlers/http.ts`
- Create: `src/bash/handlers/kubectl.ts`
- Create: `src/bash/policies/secrets.ts`
- Create: `src/bash/policies/github.ts`
- Create: `src/bash/policies/kubectl.ts`
- Create: `src/authorization.ts`
- Modify: `src/secrets.ts:1-65`
- Modify: `src/github.ts:1-164`
- Modify: `src/kubectl.ts:1-204`
- Create: `tests/bash-hard-block-policies.test.ts`

**Interfaces:**
- Consumes: normalized invocation/redirect observations from Tasks 3–6 and existing pattern/message helpers.
- Produces: `analyzeBashAuthorization()`, invocation-level deny/allow/neutral policy functions, and compatibility exports with existing public names.

- [ ] **Step 1: Write migration regression tests**

  Port current literal tests and add stateful/wrapper variants:

  ```ts
  expect(checkBashForKubectlSecret("TOOL=kubectl; strace $TOOL get secret app")).toContain("kubectl get Secret");
  expect(parseBashForSecretRead("READER=cat; $READER credentials.json")).toContain("cat");
  expect(checkBashForGithub("curl https://api.github.com/repos/o/r/issues")).toContain("Use the native gh command");
  ```

- [ ] **Step 2: Run policy migration tests and confirm failure**

  Run: `bun test tests/bash-hard-block-policies.test.ts`

  Expected: FAIL because stateful policy handlers do not exist.

- [ ] **Step 3: Move decisions to invocation-level policy functions**

  Keep pattern constants and canonical messages in their current files. Move reader redirect/operand checks, blocked GitHub-domain HTTP checks, and kubectl resource/flag logic into pure functions accepting a normalized invocation and redacted provenance. Register dedicated `cat`/reader, HTTP-tool, and `kubectl` handlers. Preserve special OpenCode/Pi behavior for `kubectl get Secret` by mapping the same invocation policy evidence in the adapter-facing compatibility function.

- [ ] **Step 4: Preserve public APIs through walker-backed compatibility wrappers**

  Define `analyzeBashAuthorization()` in `src/authorization.ts` using the walker and registry from Tasks 5–6, then reimplement `parseBashForSecretRead`, `checkBashForGithub`, `analyzeKubectl`, `checkBashForKubectlSecret`, and `summariseKubectlSecret` using that API or its redacted invocation trace. Remove their direct `parseBash()` scans. Keep return discriminants and canonical reason strings compatible with existing adapter tests.

  Run: `bun test tests/bash-hard-block-policies.test.ts tests/read-only-cli.test.ts`

  Expected: PASS.

- [ ] **Step 5: Add deny-precedence properties**

  Generate a safe invocation prefix followed by one known secret reader, blocked HTTP call, or forbidden kubectl invocation. Assert final verdict is deny regardless of preceding indeterminate evidence or wrapper placement.

## Task 8: Migrate `gh` and credential-safe read-only command policies

**Files:**
- Create: `src/bash/handlers/gh.ts`
- Create: `src/bash/handlers/read-only.ts`
- Create: `src/bash/policies/gh-api.ts`
- Create: `src/bash/policies/gh-pr-create.ts`
- Create: `src/bash/policies/read-only.ts`
- Modify: `src/gh.ts:1-89`
- Modify: `src/gh-pr-create.ts:1-515`
- Modify: `src/read-only-cli.ts:1-271`
- Modify: `src/index.ts:15-23`
- Create: `tests/bash-gh-policies.test.ts`
- Modify: `tests/gh-pr-create.test.ts:45-174`
- Modify: `tests/read-only-cli.test.ts:48-305`

**Interfaces:**
- Consumes: `CommandRegistry`, invocation cursor option state, policy config, and wrapper dispatch.
- Produces: `analyzeBashAuthorization()` and existing `analyzeGhApiCommand`, `analyzeGhPrCreateCommand`, `analyzeGhReadOnlyCommand`, `analyzeHelmReadOnlyCommand`, and `analyzeStrictReadOnlyCommand` compatibility results.

- [ ] **Step 1: Write failing stateful `gh` and read-only tests**

  Cover assignments, transparent wrappers, explicit host checks, `gh api` method precedence, unknown shell children, compound all-safe invocation, and a compound invocation containing an unknown command:

  ```ts
  expect(analyzeGhPrCreateCommand("TOOL=gh; strace $TOOL pr create --repo github.com/acme/widgets --fill", policy).kind).toBe("allow");
  expect(analyzeGhApiCommand("METHOD=GET; gh api -X $METHOD -f q=x user").kind).toBe("allow");
  expect(analyzeStrictReadOnlyCommand("TOOL=docker; $TOOL image ls", "docker").kind).toBe("allow");
  expect(analyzeStrictReadOnlyCommand("docker image ls; unknown-command", "docker").kind).toBe("defer");
  ```

- [ ] **Step 2: Run migration tests and confirm failure**

  Run: `bun test tests/bash-gh-policies.test.ts tests/gh-pr-create.test.ts tests/read-only-cli.test.ts`

  Expected: FAIL because compatibility exports still operate on flattened commands.

- [ ] **Step 3: Implement `gh` handler/subhandler grammar**

  The root `gh` handler consumes audited global flags into typed cursor options, then dispatches subhandlers for `api`, `pr`, `alias`, and extensions. The `pr` subhandler routes `create`/`new` to the repository-allowlist policy. The API subhandler preserves explicit-method-over-parameter precedence. Alias, extension execution, and unknown top-level `gh` invocations produce the current policy-specific deny evidence under `ghPrCreate`.

- [ ] **Step 4: Adapt every read-only grammar to invocation cursors**

  Move `parseAllowedFlags`, command-path extraction, protected Kubernetes-resource handling, and tool allowlists behind dedicated handlers. Each handler consumes only its documented flags, keeps unknown flags neutral, and returns safe only for its current audited command set. The generic authorization API must return allow only when every dispatched command is safe under active profiles.

  Run: `bun test tests/bash-gh-policies.test.ts tests/gh-pr-create.test.ts tests/read-only-cli.test.ts`

  Expected: PASS.

- [ ] **Step 5: Add policy properties and parser-failure preservation**

  Retain 500-case repository/organization allowlist properties. Add generated flag-position tests through wrappers. Keep `ghPrCreate` parser-unavailable behavior as deny with the deployment diagnostic, while ordinary unavailable dynamic child analysis remains neutral.

## Task 9: Wire configuration, adapters, and package checks

**Files:**
- Modify: `src/config.ts:10-80`
- Modify: `nix/permissions.nix:30-103`
- Modify: `adapters/opencode.ts:63-147`
- Modify: `adapters/pi.ts:170-229`
- Modify: `adapters/claude-code/gh_api_read_allow.ts`
- Modify: `adapters/claude-code/gh_pr_create_policy.ts`
- Modify: `adapters/claude-code/read_only_cli_allow.ts`
- Modify: `adapters/claude-code/secrets_policy.ts`
- Modify: `adapters/claude-code/github_raw_redirect.ts`
- Modify: `adapters/claude-code/kubectl_get_allow.ts`
- Modify: `flake.nix:96-338`
- Create: `tests/bash-config.test.ts`
- Create: `tests/bash-adapter.test.ts`

**Interfaces:**
- Consumes: `BashAnalysisLimits`, `analyzeBashAuthorization()`, public compatibility exports, and existing profile config.
- Produces: validated `profiles.json.bashAnalysis`, Nix options, and adapters that map walker verdicts correctly without implicit environment access.

- [ ] **Step 1: Write failing config and adapter mapping tests**

  Assert config rejects negative/fractional/non-number values and falls back to safe defaults. Assert Nix-rendered JSON contains all four limits. Stub each adapter-facing evaluator and assert allow changes a permission status only for complete-safe analysis; neutral/failure leaves the native status unchanged; deny blocks. Assert each adapter supplies `{ kind: "unavailable" }` unless its harness contract explicitly proves environment equivalence.

- [ ] **Step 2: Run config and adapter tests and confirm failure**

  Run: `bun test tests/bash-config.test.ts tests/bash-adapter.test.ts`

  Expected: FAIL because analysis-limit configuration and adapter environment capability are absent.

- [ ] **Step 3: Add validated runtime and Nix configuration**

  Add `bashAnalysis?: { maxFunctionDepth?: number; maxNestedScriptDepth?: number; maxSteps?: number; maxWorkItems?: number }` to `SafetyCoreProfileConfig`. Add `loadBashAnalysisLimits()` that accepts only positive safe integers. Add matching `mkOption` fields under `programs.safetyCorePermissions.bashAnalysis`, initially using the candidate values 128, 64, 100000, and 10000. Render the validated JSON object in `xdg.configFile."safety-core/profiles.json"` and extend Nix evaluation assertions.

- [ ] **Step 4: Migrate adapters to the unified verdict contract**

  Construct walker options using parsed limits, active profiles, and an explicit unavailable initial environment unless documented harness behavior proves equivalence. In `permission.ask`, set `output.status = "allow"` only for allow and `"deny"` only for deny; leave neutral unchanged. In hard-block hooks, block only deny. Preserve current judge invocation behavior after deterministic hard-block evaluation.

  Run: `bun test tests/bash-config.test.ts tests/bash-adapter.test.ts && nix flake check .#command-profile-tests .#gh-pr-create-profile-eval .#read-only-cli-profile-eval`

  Expected: PASS.

- [ ] **Step 5: Add packaged hook runtime coverage**

  Extend `flake.nix` runtime checks with one assignment/wrapper safe case, one indeterminate dynamic-child case that leaves permission untouched, one deny-after-indeterminate case, and a `bashAnalysis` JSON-rendering assertion. Exercise built hook bundles, not source-only imports.

## Task 10: Build the isolated real-Bash equivalence and performance suite

**Files:**
- Create: `tests/helpers/bash-oracle.ts`
- Create: `tests/bash-equivalence.test.ts`
- Create: `tests/bash-performance.test.ts`
- Modify: `flake.nix:96-114`

**Interfaces:**
- Consumes: public CST/walker authorization API and `bash`/temporary command shim processes.
- Produces: NUL-delimited real-Bash oracle traces and measured cap-exhaustion calibration evidence.

- [ ] **Step 1: Write a failing oracle fixture test**

  Under `env -i`, create a temporary executable `record-command` that writes NUL-delimited argv plus selected exported non-secret test variables to a trace file. Run scripts using that shim and compare with walker observations:

  ```ts
  const trace = await runBashOracle('F=BAR D=GAR record-command "$D" "$F"', { BASE: "root" });
  expect(trace[0]).toEqual({ argv: ["GAR", "BAR"], environment: { BASE: "root", F: "BAR", D: "GAR" } });
  ```

- [ ] **Step 2: Run the equivalence test and confirm failure**

  Run: `bun test tests/bash-equivalence.test.ts`

  Expected: FAIL because the Bash oracle helper and walker trace comparison do not exist.

- [ ] **Step 3: Implement the sandboxed Bash oracle and supported-subset corpus**

  Use `Bun.spawn` with `env: { PATH: shimDirectory, ...knownEnvironment }` and `bash --noprofile --norc -c source`. Write shim records with NUL separators; parse them without rendering values in assertion messages. Cover assignments, functions, dynamic scoping, local/export/unset, braces, subshells, conditionals, and transparent wrappers that ultimately invoke the shim. Keep unsupported syntax in separate tests asserting neutral and correct taint rather than exact trace equality.

- [ ] **Step 4: Add generated supported-subset equivalence and calibration tests**

  Generate bounded supported programs from a seeded grammar and compare their oracle trace/final environment to the walker. Generate deeply nested functions, nested `sh -c` literals, long assignment sequences, and branching work that exactly exhaust the active budgets. Measure elapsed monotonic time and record the observed value in the test output; tune the four Nix defaults if cap exhaustion materially exceeds the approximately 1,000 ms guideline on the project’s supported development platform.

  Run: `bun test tests/bash-equivalence.test.ts tests/bash-performance.test.ts`

  Expected: PASS with no secret values printed.

- [ ] **Step 5: Package the complete suite in Nix**

  Add the new tests to `command-profile-tests` or a dedicated `bash-walker-tests` flake check with Bun and Bash in `nativeBuildInputs`. Confirm the package fixture copies every required source, test helper, grammar WASM, and `node_modules` dependency.

## Task 11: Perform final verification and adversarial review

**Files:**
- Modify only files required to resolve verified reviewer findings.
- Test: all existing and newly added `tests/*.test.ts` suites and `nix flake check`.

**Interfaces:**
- Consumes: completed implementation, public API contract, design spec, and implementation plan.
- Produces: verification evidence and an adversarial review outcome with no unresolved Critical or Important findings.

- [ ] **Step 1: Run focused test suites**

  Run:

  ```bash
  bun test tests/bash-cst.test.ts tests/bash-environment.test.ts tests/bash-expand.test.ts tests/bash-runner.test.ts tests/bash-walker.test.ts tests/bash-dispatch.test.ts tests/bash-hard-block-policies.test.ts tests/bash-gh-policies.test.ts tests/bash-config.test.ts tests/bash-adapter.test.ts tests/bash-equivalence.test.ts tests/bash-performance.test.ts
  ```

  Expected: every focused test passes.

- [ ] **Step 2: Run regression and packaged checks**

  Run:

  ```bash
  bun test tests/gh-pr-create-parser-failure.test.ts tests/gh-pr-create.test.ts tests/read-only-cli.test.ts tests/opencode-read-only-cli.test.ts
  nix flake check
  ```

  Expected: every Bun test and every Nix check passes.

- [ ] **Step 3: Request an adversarial frontier-model review**

  Give the reviewer the spec, this plan, the final diff, and these required probes: escaped command names; assignment ordering; function dynamic scope; recursive functions; prefix overlays; branch disagreement; inherited-environment unavailable mode; `sh -c "$UNKNOWN"`; wrapper flag order; `xargs`/`find -exec`; deny after indeterminate; secret-value redaction; parser failure; and cap exhaustion. Require evidence-backed Critical/Important findings only.

- [ ] **Step 4: Resolve review findings and repeat affected verification**

  For each Critical or Important finding, first add a regression test that fails on the reviewed code, then make the smallest pure implementation change, rerun the focused suite named by the finding, rerun the complete commands from Steps 1–2, and request a follow-up review of the fix.

- [ ] **Step 5: Report evidence without committing**

  Report exact passing commands, measured cap-exhaustion results, review outcome, final changed files, and any remaining neutral cases. Do not claim completion before the commands and review are successful; do not commit unless explicitly authorized.
