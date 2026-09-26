# Pluggable Bash Policy Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace closed Bash profiles with source-loaded policies, implement a formally terminating JSON policy DSL, permit globally controlled additive project policies, and port every current Bash policy to the DSL.

**Architecture:** The existing Bash parser/walker remains the sole execution engine and emits immutable invocation or execution-gap events. Global trusted code sources first validate the generic policy boundary; a deterministic consuming register machine (DCRM) then supplies the project-safe JSON DSL, after which all current Bash policies migrate to DSL sources. Configuration and all sources load fatally before the agent loop, while adapters consume one generic allow/deny/defer result and trace.

**Tech Stack:** TypeScript ESM, Bun tests, Node.js 22, `web-tree-sitter`, `tree-sitter-bash`, JSON policy sources, esbuild, Nix flakes, Home Manager.

**Spec:** `docs/superpowers/specs/2026-09-21-pluggable-bash-policy-design.md`

## Global Constraints

- Core retains Bash parsing, expansion, shell state, reachability, wrappers, execution gaps, budgets, executable lookup, aggregation, and traces.
- Policies are pure single-event classifiers and cannot schedule execution or retain cross-invocation state.
- Policies receive actual modeled argv and the entire modeled environment; no input-redaction boundary may be reintroduced.
- Commands and policy diagnostics may be logged, and DSL diagnostics may interpolate any supplied value.
- Canonical source path is policy identity; digest is integrity/version metadata. There are no policy IDs or per-policy configuration schemas.
- Every current Bash policy is an explicit source; no command policy remains implicitly enabled in core.
- Per event, any deny wins; otherwise any permission allow covers an invocation. Whole-request allow requires complete analysis and coverage of every reachable invocation.
- Global configuration is authoritative and usable without Nix. Nix exposes every configurable field and is only a management/distribution layer.
- Project policies are DSL-only, nearest-project, globally gated by disabled/allowlisted/all mode, and intentionally capable of adding authorization subject to all guards.
- Missing, malformed, incompatible, or throwing configuration/policies are fatal before or during the agent loop; never downgrade them to native permissions.
- DSL validation must establish DCRM progress and finite execution. Worst-case evaluator time is `O(PB²)`, working memory is `O(P+B)`, and materialized output is `O(PB)`.
- Top-level executable selectors support exact basename and explicit exact selected/canonical/chain projections only—no selector glob or regex.
- Add focused unit tests and deterministic property tests for every changed subsystem.
- Preserve the repository’s existing Bash equivalence, replay, performance, packaging, and harness integration coverage.
- Present the final frontier-model adversarial review to the operator before making review-driven corrections.
- Do not stage, commit, amend, push, or create a pull request unless the operator explicitly requests it.

---

## File Structure

| Path | Responsibility |
| --- | --- |
| `src/policy/types.ts` | Stable event, selector, decision, source-provenance, trace, and loaded-policy contracts. |
| `src/policy/evaluate.ts` | Order-independent per-event and whole-request policy algebra. |
| `src/policy/config.ts` | Authoritative global/project config parsing, path precedence, and immutable session configuration. |
| `src/policy/load.ts` | Canonical source resolution, digesting, trusted code import, DSL compilation, and fatal diagnostics. |
| `src/policy/events.ts` | Projection from walker/dispatch state into complete policy events. |
| `src/policy/executable.ts` | Modeled PATH lookup and exact executable identity projections. |
| `src/policy/filesystem.ts` | Injectable filesystem-resolution interface and production implementation. |
| `src/policy/trace.ts` | Structured explain traces and human/JSON rendering. |
| `src/policy/session.ts` | In-process immutable snapshots and Claude manifest/digest verification. |
| `src/policy/dsl/ast.ts` | JSON AST and statically typed DCRM source model. |
| `src/policy/dsl/validate.ts` | Strict schema/type/progress validator and desugaring checks. |
| `src/policy/dsl/compile.ts` | Option/state convenience lowering into compiled DCRM programs. |
| `src/policy/dsl/evaluate.ts` | Deterministic consuming machine evaluator. |
| `src/policy/dsl/builtins.ts` | Closed, versioned total builtin catalogue. |
| `src/cli.ts` | `safety-core validate` and `safety-core explain`. |
| `policies/code/*.policy.ts` | Temporary trusted-code forms of current Bash policies for boundary validation. |
| `policies/dsl/*.policy.json` | Final DSL forms of all current Bash policy families. |
| `tests/policy-*.test.ts` | Policy algebra, source, config, session, executable, trace, and CLI tests. |
| `tests/policy-dsl-*.test.ts` | DSL grammar, validator, evaluator, properties, and complexity tests. |
| `tests/policy-parity.test.ts` | Old/code/DSL differential corpus during migration. |
| `nix/permissions.nix` | Home Manager options for authoritative config and installed source paths. |
| `package.nix`, `flake.nix` | Package policy files, CLI, hooks, extensions, and runtime checks. |

## Task 1: Define the Open Policy Event and Decision Algebra

**Files:**
- Create: `src/policy/types.ts`
- Create: `src/policy/evaluate.ts`
- Create: `tests/policy-evaluate.test.ts`
- Modify: `src/index.ts`

**Interfaces:**
- Produces: `BashPolicyEvent`, `InvocationView`, `ExecutionGapView`, `BashPolicy`, `PolicyDecision`, `PolicyTrace`, and `evaluatePolicyEvents(events, policies, analysis)`.
- Consumes later: every source loader, walker bridge, DSL compiler, adapter, and explain command.

- [ ] **Step 1: Write failing decision-algebra examples and generated properties**

  Define mock source-addressed policies and assert guard success cannot grant, any event denial wins, any permission allow covers one invocation, separate policies may cover separate invocations, gaps prevent allow, gap denials deny, and all policy/event permutations retain the same aggregate:

  ```ts
  expect(evaluatePolicyEvents([invocation("git"), invocation("docker")], [
    policy("/p/git", "permission", event => basename(event) === "git" ? allow("git read") : ignore()),
    policy("/p/docker", "permission", event => basename(event) === "docker" ? allow("docker read") : ignore()),
  ], completeAnalysis())).toMatchObject({ decision: "allow" });

  expect(evaluatePolicyEvents([executionGap("opaque-child")], [
    policy("/p/gap", "guard", () => deny("opaque execution forbidden")),
  ], incompleteAnalysis())).toMatchObject({ decision: "deny" });
  ```

- [ ] **Step 2: Run the focused test and verify the missing-module failure**

  Run: `bun test tests/policy-evaluate.test.ts`

  Expected: FAIL because `src/policy/types.ts` and `evaluatePolicyEvents` do not exist.

- [ ] **Step 3: Implement immutable open contracts and aggregation**

  Add exact contracts:

  ```ts
  export type PolicyDiagnosticPart =
    | { readonly kind: "literal"; readonly value: string }
    | { readonly kind: "value"; readonly value: unknown };
  export type PolicyTemplateValue = readonly PolicyDiagnosticPart[];

  export type PolicyDecision =
    | { readonly kind: "allow"; readonly reason: PolicyTemplateValue; readonly audit?: Readonly<Record<string, unknown>> }
    | { readonly kind: "deny"; readonly reason: PolicyTemplateValue; readonly audit?: Readonly<Record<string, unknown>> }
    | { readonly kind: "defer"; readonly reason?: PolicyTemplateValue }
    | { readonly kind: "ignore" };

  export interface LoadedBashPolicy {
    readonly source: PolicySourceIdentity;
    readonly layer: "guard" | "permission";
    readonly select: readonly BashPolicySelector[];
    evaluate(event: BashPolicyEvent): PolicyDecision;
  }
  ```

  Enforce guard result types at load/validation and defensively reject a runtime guard allow as fatal. Preserve full event values in traces.

- [ ] **Step 4: Run unit and property tests**

  Run: `bun test tests/policy-evaluate.test.ts`

  Expected: PASS for truth tables and at least 1,000 deterministic policy/event order permutations.

- [ ] **Step 5: Review the boundary before integrating the walker**

  Confirm no union enumerates policy names, no aggregation inspects a source path to infer semantics, no policy ordering affects outcomes, and no event value is redacted or dropped.

## Task 2: Implement Authoritative Configuration and Source Loading

**Files:**
- Create: `src/policy/config.ts`
- Create: `src/policy/load.ts`
- Create: `tests/policy-config.test.ts`
- Create: `tests/policy-loader.test.ts`
- Modify: `src/index.ts`

**Interfaces:**
- Consumes: `LoadedBashPolicy` from Task 1.
- Produces: `loadGlobalPolicyConfig(env)`, `resolveSessionPolicyConfig(config, cwd)`, `loadPolicySet(resolved)`, `PolicyStartupError`, and immutable `LoadedPolicySet`.

- [ ] **Step 1: Write failing precedence, canonicalization, and fatal-loading tests**

  Cover environment-variable precedence by presence, absolute/non-empty validation, no missing-file fallback, unknown-key rejection, source-relative paths, canonical duplicate collapse, identical bytes at distinct paths remaining distinct, code-only-global enforcement, and complete-value loading.

  ```ts
  expect(() => loadGlobalPolicyConfig({
    SAFETY_CORE_CONFIG_HOME: "relative",
    HOME: "/home/test",
  })).toThrow(PolicyStartupError);
  expect(loaded.sources.map(source => source.canonicalPath)).toEqual([realA, realB]);
  ```

- [ ] **Step 2: Run loader tests and verify failure**

  Run: `bun test tests/policy-config.test.ts tests/policy-loader.test.ts`

  Expected: FAIL because the authoritative config and source loader do not exist.

- [ ] **Step 3: Implement strict config parsing and source provenance**

  Parse only the spec’s `version`, `policies`, `projectPolicies`, and `bashAnalysis` fields. Canonicalize source paths, hash exact bytes with SHA-256, use canonical path as identity, and return frozen values. Add a loader-injected `importCodePolicy(url)` so tests use deterministic fixtures.

- [ ] **Step 4: Implement trusted `.policy.mjs` loading**

  Accept one frozen `apiVersion: 1` policy export, reject relative runtime imports through a pre-import module-specifier scan, enforce guard/permission decision capabilities, and wrap import/initialization failures in source-positioned `PolicyStartupError`. Do not add a generic policy config payload.

- [ ] **Step 5: Run focused tests**

  Run: `bun test tests/policy-config.test.ts tests/policy-loader.test.ts tests/bash-config.test.ts`

  Expected: new tests PASS; legacy tests remain unchanged until the atomic config cutover task.

## Task 3: Bridge the Bash Walker to Generic Policy Events

**Files:**
- Create: `src/policy/events.ts`
- Modify: `src/bash/dispatch.ts`
- Modify: `src/bash/walker.ts`
- Modify: `src/bash/runner.ts`
- Modify: `src/bash/outcome.ts`
- Modify: `src/authorization.ts`
- Modify: `src/index.ts`
- Create: `tests/policy-events.test.ts`
- Modify: `tests/bash-dispatch.test.ts`
- Modify: `tests/bash-configured.test.ts`

**Interfaces:**
- Consumes: Task 1 policy algebra and the existing normalized command/walker context.
- Produces: `analyzeBashWithPolicies(options): BashPolicyEvaluation` and complete invocation/gap event traces.

- [ ] **Step 1: Write failing event-projection tests**

  Assert events retain exact known argv/environment canaries, explicit unknowns, redirects, assignments, provenance, pipeline state, process effect, source coordinates, and gaps. Assert a later deny survives an earlier gap.

  ```ts
  expect(event.environment.CANARY).toEqual({ kind: "known", value: "exact-value" });
  expect(event.argv[0]).toEqual({ kind: "unknown", reason: expect.any(Object) });
  ```

- [ ] **Step 2: Run the focused tests and verify failure**

  Run: `bun test tests/policy-events.test.ts tests/bash-dispatch.test.ts`

  Expected: FAIL because dispatch emits closed `PolicyEvidence` rather than generic events.

- [ ] **Step 3: Add event projection without changing structural ownership**

  Keep `StructuralHandler` and continuation scheduling unchanged. Dispatch emits an immutable event before policy classification; unresolved structural children emit `ExecutionGapView`. Pass complete modeled values rather than the current redacted evidence projection.

- [ ] **Step 4: Add the generic authorization entry point in shadow mode**

  Implement `analyzeBashWithPolicies()` beside `evaluateConfiguredBash()`. Use Task 1 aggregation, preserve runner budgets and deny traversal, and expose a complete trace. Do not switch adapters yet.

- [ ] **Step 5: Run walker and regression suites**

  Run: `bun test tests/policy-events.test.ts tests/policy-evaluate.test.ts tests/bash-dispatch.test.ts tests/bash-walker.test.ts tests/bash-runner.test.ts tests/bash-configured.test.ts`

  Expected: PASS with old and shadow generic evaluation coexisting.

## Task 4: Migrate Baseline Guards to Trusted Code Sources

**Files:**
- Create: `policies/code/secret-read.policy.ts`
- Create: `policies/code/github-http.policy.ts`
- Create: `policies/code/kubectl.policy.ts`
- Create: `policies/code/unsupported-shell-source.policy.ts`
- Create: `tests/policy-code-guards.test.ts`
- Create: `tests/policy-parity.test.ts`
- Modify: `package.nix`

**Interfaces:**
- Consumes: `LoadedBashPolicy`, generic events, and current pure policy analyzers.
- Produces: four self-contained bundled `.policy.mjs` artifacts and old-vs-code differential fixtures.

- [ ] **Step 1: Write failing guard parity tables and generated properties**

  Reuse current secret reader/redirect, GitHub HTTP, kubectl, wrapper, unresolved-source, ordering, and deny-after-indeterminate corpora. Compare decisions, reasons, and audit values between current evaluation and generic code policies.

- [ ] **Step 2: Run parity tests and verify missing sources**

  Run: `bun test tests/policy-code-guards.test.ts tests/policy-parity.test.ts`

  Expected: FAIL because no code policy sources are packaged.

- [ ] **Step 3: Implement guard definitions as event classifiers**

  Wrap existing pure analyzers without letting guard-safe results return allow: prohibited forms return deny; safe/non-applicable forms return ignore. Move unsupported-shell-source behavior to gap events. Preserve exact actual values in diagnostics/audit outputs.

- [ ] **Step 4: Bundle each source independently**

  Extend `package.nix` with `mkCodePolicy` using esbuild so each output is one self-contained import-free `.policy.mjs`. Expose a `codePolicies` attribute set for tests and later Nix configuration.

- [ ] **Step 5: Run focused and packaged guard checks**

  Run: `bun test tests/policy-code-guards.test.ts tests/policy-parity.test.ts tests/bash-hard-block-policies.test.ts tests/bash-guards.test.ts && nix build .#checks.$(nix eval --raw --impure --expr builtins.currentSystem).hooks-runtime`

  Expected: PASS without switching production configuration.

## Task 5: Migrate Permission Profiles to Trusted Code Sources

**Files:**
- Create: `policies/code/generic-read-only.policy.ts`
- Create: `policies/code/gh-read-only.policy.ts`
- Create: `policies/code/helm-read-only.policy.ts`
- Create: `policies/code/strict-read-only.policy.ts`
- Create: `policies/code/gh-api.policy.ts`
- Create: `policies/code/gh-pr-create.policy.ts`
- Create: `scripts/render-gh-pr-create-code-policy.ts`
- Create: `tests/policy-code-permissions.test.ts`
- Modify: `tests/policy-parity.test.ts`
- Modify: `package.nix`

**Interfaces:**
- Consumes: current policy analyzers and Task 4 bundling.
- Produces: complete code policies for every current permission family and a transitional generator embedding PR allowlists into a complete source.

- [ ] **Step 1: Write failing permission parity tests**

  Cover generic/Git/Tea/checksum, GitHub, Helm, every strict executable, `gh api`, PR creation, environment routes, path-qualified commands, wrappers, aliases, option-order permutations, and compound commands covered by separate policies.

- [ ] **Step 2: Run focused tests and verify failure**

  Run: `bun test tests/policy-code-permissions.test.ts tests/policy-parity.test.ts`

  Expected: FAIL because permission code sources and source generation are absent.

- [ ] **Step 3: Implement complete permission code definitions**

  Convert analyzer allow/defer/deny results directly. A policy ignores executables/forms outside its domain. Remove assumptions that foreign policy evidence forces defer; generic aggregation now permits separate policies to cover separate invocations.

- [ ] **Step 4: Implement transitional PR policy source generation**

  `renderGhPrCreateCodePolicy({ allowedRepositories, allowedOrganizations })` must emit deterministic TypeScript source whose bundled module contains those literal lists and no runtime config lookup. Add snapshot tests proving values alter source bytes/digest and malformed values are rejected before generation.

- [ ] **Step 5: Run permission, generated-property, and package tests**

  Run: `bun test tests/policy-code-permissions.test.ts tests/policy-parity.test.ts tests/read-only-cli.test.ts tests/git-read-only-policy.test.ts tests/gh-read-only-policy.test.ts tests/gh-pr-create.test.ts`

  Expected: PASS for exact parity except separately asserted intended multi-policy coverage changes.

## Task 6: Cut Over Global Config, Adapters, and Add Validate/Explain

**Files:**
- Create: `src/policy/trace.ts`
- Create: `src/cli.ts`
- Create: `tests/policy-cli.test.ts`
- Modify: `src/config.ts`
- Modify: `src/authorization.ts`
- Modify: `adapters/opencode.ts`
- Modify: `adapters/pi.ts`
- Modify: `adapters/claude-code/_bash_policy.ts`
- Modify: `adapters/claude-code/_shared.ts`
- Modify: `nix/permissions.nix`
- Modify: `package.nix`
- Modify: `flake.nix`
- Modify: `tests/bash-config.test.ts`
- Modify: adapter tests

**Interfaces:**
- Consumes: global code policies and generic evaluator.
- Produces: authoritative `config.json`, generic adapter mapping, `safety-core validate`, and `safety-core explain --json -- <source>`.

- [ ] **Step 1: Write failing CLI, config-cutover, and adapter tests**

  Assert `profiles.json` is rejected/unused, missing config aborts startup, validate reports canonical sources/digests, explain includes exact canary argv/environment and every source decision, allow/deny/defer map generically, and runtime policy exceptions never fall back.

- [ ] **Step 2: Run focused tests and verify failure**

  Run: `bun test tests/policy-cli.test.ts tests/bash-config.test.ts tests/claude-code-bash-policy.test.ts tests/opencode-bash-guards.test.ts tests/pi-adapter.test.ts`

  Expected: FAIL against the legacy profile loader and policy-specific adapter switches.

- [ ] **Step 3: Atomically replace runtime profile configuration**

  Make `src/config.ts` a compatibility-free re-export or remove it after updating imports. Render `xdg.configFile."safety-core/config.json"` with `version`, source paths, project mode/roots, and analysis limits. Replace all profile toggles with `policySources: listOf path` and project-policy options. Nix generates the transitional PR source when requested by an explicit helper option, not a runtime config payload.

- [ ] **Step 4: Implement production trace and CLI paths**

  `validate` invokes the production config/source loader and exits nonzero on `PolicyStartupError`. `explain` initializes the parser, executes `analyzeBashWithPolicies`, and renders deterministic human or versioned JSON traces. Package an executable Node 22 CLI.

- [ ] **Step 5: Switch adapters to one immutable loaded set and generic mapping**

  Remove policy-name presentation branches. Guard or permission deny blocks; complete covered analysis allows once; uncovered/incomplete defers; fatal load/evaluation errors poison/reject the session. Keep judge invocation after deterministic denial checks.

- [ ] **Step 6: Run focused and packaged checks**

  Run: `bun test tests/policy-cli.test.ts tests/bash-config.test.ts tests/claude-code-bash-policy.test.ts tests/opencode-bash-guards.test.ts tests/opencode-read-only-cli.test.ts tests/pi-adapter.test.ts && nix flake check`

  Expected: PASS using only `config.json` and explicit code source paths.

## Task 7: Add Executable PATH and Symlink Identity Resolution

**Files:**
- Create: `src/policy/filesystem.ts`
- Create: `src/policy/executable.ts`
- Create: `tests/policy-executable.test.ts`
- Modify: `src/policy/types.ts`
- Modify: `src/policy/events.ts`
- Modify: adapters to supply working directory/resolver context

**Interfaces:**
- Produces: `resolveExecutableIdentity(spelling, environment, cwd, resolver): ExecutableIdentity` and injectable `ExecutableFilesystem`.
- Consumes later: exact basename/selected/canonical/chain selectors in code and DSL policies.

- [ ] **Step 1: Write table-driven fake-filesystem failures and properties**

  Cover ordered PATH, empty/relative entries, unknown earlier entries, direct paths, directory/relative symlinks, `..`, loops/depth, broken links, permission/I/O/mutation, Nix chains, and projection conflicts. Assert deterministic transcripts and “added ambiguity never creates a path-dependent match.”

- [ ] **Step 2: Run tests and verify failure**

  Run: `bun test tests/policy-executable.test.ts`

  Expected: FAIL because executable identity has no resolver.

- [ ] **Step 3: Implement the injected resolver and typed incomplete results**

  Preserve kernel component order and relative symlink target bases. Never skip an uncertain earlier PATH candidate. Return `qualification: "unknown"` for unresolved spelling. Record selected path, chain, canonical target, or exact typed failure.

- [ ] **Step 4: Add exact projection selector semantics**

  Implement basename, selected-path, canonical-target, and chain-contains exact/case-sensitive matching only. Keep path uncertainty available inside events rather than globally converting basename policies to defer.

- [ ] **Step 5: Run identity, walker, replay, and adapter tests**

  Run: `bun test tests/policy-executable.test.ts tests/policy-events.test.ts tests/bash-equivalence.test.ts tests/opencode-history-adapter.test.ts tests/claude-code-bash-policy.test.ts tests/pi-adapter.test.ts`

  Expected: PASS with offline replay explicitly marking unavailable resolution rather than consulting unrelated host state.

## Task 8: Define and Validate the JSON DCRM Language

**Files:**
- Create: `src/policy/dsl/ast.ts`
- Create: `src/policy/dsl/validate.ts`
- Create: `src/policy/dsl/compile.ts`
- Create: `src/policy/dsl/builtins.ts`
- Create: `tests/policy-dsl-validate.test.ts`
- Create: `docs/policy-dsl.md`

**Interfaces:**
- Produces: `parsePolicyDocument(json)`, `validatePolicyDocument(value)`, `compilePolicyDocument(ast): CompiledPolicyProgram`, and the exact v1 builtin catalogue.

- [ ] **Step 1: Write failing grammar/type/progress tests**

  Test exact version/keys, one start state, resolved references, register/action typing, guard-no-allow, default/end terminals, consuming transitions, cluster-byte progress, acyclic fragment expansion, non-nested single-run folds, size caps, and rejection of unknown built-ins.

- [ ] **Step 2: Run validator tests and verify failure**

  Run: `bun test tests/policy-dsl-validate.test.ts`

  Expected: FAIL because the DSL modules do not exist.

- [ ] **Step 3: Implement strict AST parsing and type checking**

  Use handwritten discriminant checks; add no schema/runtime dependency. Reject unknown keys. Implement fixed register domains, `Case { when, action }`, transition/terminal distinction, option declarations, finite templates, and finite audit objects.

- [ ] **Step 4: Implement desugaring and static progress validation**

  Expand machine-wide/state-local options into ordered consuming cases, expand only acyclic bounded fragments, assign internal cluster-byte state, and reject any compiled nonterminal edge that does not decrease the specified remaining-token-boundary-plus-byte measure.

- [ ] **Step 5: Freeze the initial builtin inventory from migration needs**

  Add only total operations required by the Task 4–5 corpus: exact/string-set tests, ASCII case conversion, prefix/suffix/substring, basename/components, fixed split, bounded integers, safe glob, linear regex, URL/repository parsing, environment lookup, and redirect/assignment/provenance/pipeline/process predicates. Document each signature and complexity in `docs/policy-dsl.md`.

- [ ] **Step 6: Run validator properties and documentation checks**

  Run: `bun test tests/policy-dsl-validate.test.ts`

  Expected: PASS for generated valid/invalid machines and linear validation-size measurements.

## Task 9: Implement the Deterministic DSL Evaluator and Resource Tests

**Files:**
- Create: `src/policy/dsl/evaluate.ts`
- Create: `tests/policy-dsl-evaluate.test.ts`
- Create: `tests/policy-dsl-performance.test.ts`
- Modify: `src/policy/load.ts`
- Modify: `src/policy/trace.ts`

**Interfaces:**
- Consumes: `CompiledPolicyProgram` from Task 8.
- Produces: `createDslPolicy(program, source): LoadedBashPolicy` and complete machine-step explain traces.

- [ ] **Step 1: Write failing evaluator examples and generated halting properties**

  Cover first-match order, pre-state guards, captures, simultaneous register updates, token and cluster-byte consumption, separate/attached/equals option values, clusters, conflicts, duplicates, `--`, EOF/default, cached folds, exact unknown/absent handling, and arbitrary value interpolation.

- [ ] **Step 2: Run evaluator tests and verify failure**

  Run: `bun test tests/policy-dsl-evaluate.test.ts tests/policy-dsl-performance.test.ts`

  Expected: FAIL because no DCRM evaluator exists.

- [ ] **Step 3: Implement one-configuration deterministic evaluation**

  Maintain `(state, argvIndex, clusterByteIndex, registers, foldCache, event)` only. Never fork execution configurations. Evaluate ordered options/cases, apply updates simultaneously, consume input, and return a terminal decision with source/JSON-pointer trace provenance.

- [ ] **Step 4: Add finite-resource properties**

  Generate validator-accepted machines and finite events, assert every run terminates within the derived maximum consuming steps, measure adversarial `P`/`B` matrices against `O(PB²)`, assert working structures are bounded by compiled declarations, and assert output length remains within `O(PB)`.

- [ ] **Step 5: Load global DSL sources and explain their steps**

  Extend `loadPolicySet` for `.policy.json`, preserving canonical source identity/digest and producing fatal source-positioned validation diagnostics. Add human and JSON trace rendering for state transitions and decisions.

- [ ] **Step 6: Run all DSL tests**

  Run: `bun test tests/policy-dsl-validate.test.ts tests/policy-dsl-evaluate.test.ts tests/policy-dsl-performance.test.ts tests/policy-cli.test.ts`

  Expected: PASS.

## Task 10: Enable Globally Gated Project DSL Policies

**Files:**
- Modify: `src/policy/config.ts`
- Modify: `src/policy/load.ts`
- Create: `tests/policy-project-config.test.ts`
- Modify: `tests/policy-cli.test.ts`
- Modify: adapter startup tests

**Interfaces:**
- Produces: nearest-project discovery and additive DSL source resolution in the immutable session snapshot.

- [ ] **Step 1: Write failing project discovery/trust properties**

  Cover disabled/allowlisted/all, exact canonical roots, nearest ancestor only, no parent cascade, nested working directories, relative and absolute DSL paths, code rejection, symlinked roots, duplicate global/project source references, and project policies expanding allow while global deny still wins.

- [ ] **Step 2: Run project tests and verify failure**

  Run: `bun test tests/policy-project-config.test.ts`

  Expected: FAIL because project configuration is not loaded.

- [ ] **Step 3: Implement candidate discovery before source loading**

  Search ancestors for the nearest `.safety-core/config.json`, canonicalize its parent, apply global mode/root trust, strictly parse only `version` and `policies`, resolve paths from the project root, and reject every non-`.policy.json` source.

- [ ] **Step 4: Merge sources additively into one immutable startup set**

  Global sources load first for trace presentation only; evaluation remains order-independent. Collapse identical canonical references once. Include global/project config bytes and every source digest in the session snapshot.

- [ ] **Step 5: Run project, CLI, config, and adapter startup tests**

  Run: `bun test tests/policy-project-config.test.ts tests/policy-config.test.ts tests/policy-loader.test.ts tests/policy-cli.test.ts tests/claude-code-bash-policy.test.ts tests/opencode-bash-guards.test.ts tests/pi-adapter.test.ts`

  Expected: PASS.

## Task 11: Port All Guard Policies to DSL

**Files:**
- Create: `policies/dsl/secret-read.policy.json`
- Create: `policies/dsl/github-http.policy.json`
- Create: `policies/dsl/kubectl.policy.json`
- Create: `policies/dsl/unsupported-shell-source.policy.json`
- Modify: `tests/policy-parity.test.ts`
- Modify: guard policy tests
- Modify: `package.nix`

**Interfaces:**
- Consumes: DSL compiler/evaluator and code guard sources.
- Produces: DSL parity for all invocation and gap guard families.

- [ ] **Step 1: Add code-vs-DSL differential tests before policy files**

  Run the complete current guard corpus and generated argument/wrapper/order cases through both implementations. Compare decision kind, reason, suggestion, audit values, and selected source family; explicitly preserve stronger intentional outcomes only with named assertions.

- [ ] **Step 2: Run parity and verify missing DSL sources**

  Run: `bun test tests/policy-parity.test.ts tests/bash-hard-block-policies.test.ts tests/bash-guards.test.ts`

  Expected: FAIL because guard DSL files do not exist.

- [ ] **Step 3: Encode secret, HTTP, kubectl, and gap guards**

  Use all-invocation selectors for redirects, exact basename selectors for readers/HTTP/kubectl, gap selectors for unsupported shell source, finite tables for command/resource categories, and only reviewed general built-ins. Safe guard paths return ignore, never allow.

- [ ] **Step 4: Switch packaged guard source references to DSL**

  Keep code sources only in parity tests. Package DSL files unchanged and make generated global configuration reference them.

- [ ] **Step 5: Run parity, hard-block, adapter, and package checks**

  Run: `bun test tests/policy-parity.test.ts tests/bash-hard-block-policies.test.ts tests/bash-guards.test.ts tests/opencode-bash-guards.test.ts tests/claude-code-bash-policy.test.ts tests/pi-adapter.test.ts && nix flake check`

  Expected: PASS.

## Task 12: Port Every Permission Policy to DSL

**Files:**
- Create: `policies/dsl/generic-read-only.policy.json`
- Create: `policies/dsl/gh-read-only.policy.json`
- Create: `policies/dsl/helm-read-only.policy.json`
- Create: one `policies/dsl/strict-<tool>.policy.json` per current strict executable family
- Create: `policies/dsl/gh-api.policy.json`
- Create: generated `gh-pr-create` DSL source support
- Modify: `tests/policy-parity.test.ts`
- Modify: all read-only/GitHub policy tests
- Modify: `nix/permissions.nix`
- Modify: `package.nix`

**Interfaces:**
- Produces: complete DSL-only current Bash policy inventory and final removal of migrated code implementations.

- [ ] **Step 1: Extend differential tests to every permission family**

  Include the pinned GH command inventory, every strict command path, aliases, all option forms/orderings, unknown values, environment routes, explicit executable paths, mixed-policy compound commands, API endpoints/methods, and PR allowlist properties.

- [ ] **Step 2: Run parity and verify missing DSL policies**

  Run: `bun test tests/policy-parity.test.ts tests/read-only-cli.test.ts tests/git-read-only-policy.test.ts tests/gh-read-only-policy.test.ts tests/gh-pr-create.test.ts tests/bash-gh-policies.test.ts`

  Expected: FAIL until each DSL source is present.

- [ ] **Step 3: Port generic, Helm, and strict read-only tables**

  Encode reusable audited command paths as finite literal tables, standard option declarations, secret-shaped operand checks, environment/redirect/provenance restrictions, and exact basename/path projection intent. Generate separate complete policy files rather than runtime parameters.

- [ ] **Step 4: Port GitHub policies and generated PR allowlists**

  Encode audited `gh` paths, API parsing, alias/extension restrictions, environment routes, repository normalization, and noninteractive PR requirements. Replace the transitional code-source renderer with deterministic complete DSL-source generation for allowlists; the global config references the generated file.

- [ ] **Step 5: Remove migrated code policy implementations**

  Delete `policies/code/*.policy.ts` and the transitional PR code renderer after differential tests pass. Retain only generic trusted-code API fixtures proving future code policies still load.

- [ ] **Step 6: Run the complete policy and property suite**

  Run: `bun test tests/policy-parity.test.ts tests/read-only-cli.test.ts tests/git-read-only-policy.test.ts tests/gh-read-only-policy.test.ts tests/gh-pr-create.test.ts tests/bash-gh-policies.test.ts tests/bash-configured.test.ts tests/opencode-read-only-cli.test.ts`

  Expected: PASS with production configuration referencing DSL policies only.

## Task 13: Enforce Session Immutability and Finalize Packaging/Documentation

**Files:**
- Create: `src/policy/session.ts`
- Create: `tests/policy-session.test.ts`
- Modify: Claude/OpenCode/Pi adapters
- Modify: `src/cli.ts`
- Modify: `nix/permissions.nix`
- Modify: `package.nix`
- Modify: `flake.nix`
- Modify: `README.md`
- Modify: `docs/read-only-command-profiles.md`
- Create: `docs/policy-authoring.md`
- Create: `docs/executable-identity-limitations.md`

**Interfaces:**
- Produces: immutable in-process snapshots, Claude session manifests, final package outputs, direct/Nix setup docs, and required limitations documentation.

- [ ] **Step 1: Write failing lifecycle and poisoning tests**

  Assert OpenCode/Pi retain one loaded set, source changes require restart, Claude SessionStart writes source/config digests keyed by session ID, isolated hooks reject changed/missing bytes, and every adapter remains poisoned after a runtime policy exception.

- [ ] **Step 2: Run lifecycle tests and verify failure**

  Run: `bun test tests/policy-session.test.ts tests/claude-code-event-handlers.test.ts tests/opencode-bash-guards.test.ts tests/pi-adapter.test.ts`

  Expected: FAIL because session manifests and poisoned runtime state are absent.

- [ ] **Step 3: Implement immutable session snapshots**

  Keep loaded objects in OpenCode/Pi. For Claude, write a manifest under the harness runtime state keyed by `session_id`, selected project root, config digests, canonical sources, and source digests; every command hook verifies bytes before loading. Changed or missing bytes hard-fail until a new session.

- [ ] **Step 4: Finalize package and Nix interfaces**

  Package the CLI, core, parser assets, DSL sources, and adapter artifacts. Nix options exactly mirror authoritative config and include helpers to install/reference policy files and generate complete PR policy DSL. Update flake runtime checks to create `config.json` and exercise packaged validate/explain/hooks.

- [ ] **Step 5: Write direct-user, authoring, and limitations documentation**

  Document global/project schemas, source identity, code trust, DCRM syntax, exact decisions, option parsing, finite-resource proof, complete-value diagnostics, project authorization expansion, PATH/symlink projections, TOCTOU, Nix links, wrappers/shims, hard links/bind mounts, and execution-broker non-goals.

- [ ] **Step 6: Run lifecycle, package, and documentation-linked tests**

  Run: `bun test tests/policy-session.test.ts tests/policy-cli.test.ts tests/claude-code-event-handlers.test.ts tests/opencode-bash-guards.test.ts tests/pi-adapter.test.ts && nix flake check`

  Expected: PASS.

## Task 14: Final Verification and Operator-Gated Adversarial Review

**Files:**
- Modify only files required by operator-approved review corrections.
- Test: all `tests/*.test.ts`, `tests/test_replay_batches.py`, packaged checks, and Nix flake checks.

**Interfaces:**
- Consumes: completed implementation, approved spec, and this plan.
- Produces: reproducible verification evidence and an operator-discussed adversarial review.

- [ ] **Step 1: Run focused policy-platform verification**

  Run:

  ```bash
  bun test tests/policy-evaluate.test.ts tests/policy-config.test.ts tests/policy-loader.test.ts tests/policy-events.test.ts tests/policy-executable.test.ts tests/policy-dsl-validate.test.ts tests/policy-dsl-evaluate.test.ts tests/policy-dsl-performance.test.ts tests/policy-project-config.test.ts tests/policy-cli.test.ts tests/policy-session.test.ts tests/policy-parity.test.ts
  ```

  Expected: every focused test passes.

- [ ] **Step 2: Run the complete repository and packaged verification**

  Run:

  ```bash
  bun test tests/*.test.ts
  python -m unittest tests/test_replay_batches.py
  nix flake check
  ```

  Expected: every Bun, Python, package, hook-runtime, Nix evaluation, and flake check passes.

- [ ] **Step 3: Run explicit production CLI smoke tests**

  With a temporary non-secret test configuration, run packaged `safety-core validate`, one allowed explain case, one denied explain case, one uncovered case, one project-additive case, and one fatal invalid-source case. Expected: exit statuses and JSON decisions match the spec, and exact synthetic argv/environment canaries appear unchanged in explain output.

- [ ] **Step 4: Request the required frontier-model adversarial review**

  Give the reviewer the spec, plan, final diff, and verification logs. Require probes for source identity/canonicalization, project authorization expansion, policy overlap, gap denial, arbitrary interpolation, code-source trust, fatal startup/runtime failure, DCRM progress/type soundness, `O(PB²)` behavior, option ambiguity, unknown values, PATH ordering, symlink projection conflicts, TOCTOU documentation, adapter poisoning, and package/runtime divergence.

- [ ] **Step 5: Present the review to the operator before corrections**

  Report every Critical and Important finding with evidence, likely scope, and proposed disposition. Stop and wait for explicit operator discussion/approval before changing implementation in response.

- [ ] **Step 6: Apply only approved corrections with TDD**

  For each approved finding, first add a regression/property test that fails, make the smallest structural correction, rerun its focused suite, then repeat Steps 1–3. Request follow-up review for changed threat-model boundaries.

- [ ] **Step 7: Report completion evidence without committing**

  Report exact commands and outputs, performance bounds, migrated source inventory, package artifacts, adversarial-review disposition, changed files, and remaining documented limitations. Do not claim completion before fresh verification succeeds, and do not commit unless explicitly authorized.
