# Task 9 Report: Deterministic DSL Evaluator and Resource Tests

## RED

Created `tests/policy-dsl-evaluate.test.ts` and
`tests/policy-dsl-performance.test.ts` before the evaluator existed.

Command:

```text
bun test tests/policy-dsl-evaluate.test.ts tests/policy-dsl-performance.test.ts
```

Output:

```text
Cannot find module '../src/policy/dsl/evaluate.ts'
0 pass, 2 fail, 2 errors
```

## GREEN

Implemented a pure deterministic consuming-register-machine evaluator. Each
run starts with one state, argv index, cluster-byte index, fixed register
record, per-event fold cache, and immutable event; it neither forks nor keeps
cross-event state.

The evaluator implements ordered lowered options/cases, pre-update guards,
simultaneous updates, required/optional/absent option values, separate,
attached-short, equals-long, and short-cluster parsing, `--`, EOF/default
terminals, unknown input propagation, finite template/audit interpolation,
per-event cached folds, and JSON-pointer machine-step provenance.

Global `.policy.json` sources are now parsed, validated, compiled, and loaded
with the same canonical source identity and digest as code policies. DSL
validation failures are fatal `PolicyStartupError`s with their JSON pointer.
Project source loading remains rejected.

Policy event traces now carry DSL steps, and explain rendering exposes them in
both human and JSON forms.

## Files

- Added `src/policy/dsl/evaluate.ts`
- Added `tests/policy-dsl-evaluate.test.ts`
- Added `tests/policy-dsl-performance.test.ts`
- Updated `src/policy/config.ts`
- Updated `src/policy/evaluate.ts`
- Updated `src/policy/load.ts`
- Updated `src/policy/trace.ts`
- Updated `src/policy/types.ts`
- Updated `tests/policy-config.test.ts`
- Updated `tests/policy-loader.test.ts`

## Tests

Focused command:

```text
bun test tests/policy-dsl-validate.test.ts tests/policy-dsl-evaluate.test.ts tests/policy-dsl-performance.test.ts tests/policy-cli.test.ts tests/policy-loader.test.ts tests/policy-config.test.ts
```

Output:

```text
50 pass
0 fail
19531 expect() calls
```

The generated properties cover 128 validator-accepted finite machines and a
4-by-4 practical option-count/cluster-byte matrix. They assert consuming-step
halting bounds, one trace entry per consumed cluster byte, fixed compiled case
bounds, and linear trace output size.

Full command:

```text
bun test
```

Output:

```text
452 pass
13 fail
10 errors
43709 expect() calls
```

The full-suite failures are outside this task: ten test modules cannot import
pre-existing missing exports from `src/index.ts`; `gh-pr-create-parser-failure`
also fails for that missing export boundary; and two existing
`policy-evaluate.test.ts` expectations receive `defer` for invocation events
with unknown missing environment bindings. The focused Task 9 suite is green.

## Commit

Commit created immediately after this report: `feat(policy): evaluate DSL policies`.

## Concerns

- No adversarial reviewer was dispatched, per the operator's explicit
  instruction not to dispatch subagents or reviewers. No follow-up corrections
  are pending from such a review.
- The full repository suite remains blocked by unrelated missing public exports
  and pre-existing policy evaluation expectations described above.

## Fix Round 1/5

### RED

Added regressions before changing the evaluator or validator:

```text
bun test tests/policy-dsl-evaluate.test.ts tests/policy-dsl-validate.test.ts
```

Output:

```text
20 pass
4 fail
707 expect() calls
```

Failures demonstrated that `--output=value` with separate-only forms fell
through to a generic transition, unknown input through `parseBoundedInt` then
`boundedIntAtMost` threw `TypeError: Cannot convert a symbol to a number`,
shared fragment expansion produced occurrence-derived pointers, and `[z-a]`
passed validation despite JavaScript rejecting it.

### Fixes

- Reserved every syntactically explicit declared option spelling before generic
  cases, independently of enabled forms. `--` disables that reservation for the
  rest of the event and remains disabled across generic transitions.
- Propagated compiler-owned JSON pointers into each lowered case, including
  repeated shared/nested fragment expansion sites.
- Short-circuited unknown operands for builtins that require known operands;
  unknown guards now select the program terminal rather than coercing a symbol.
- Added native compilation after restricted-regex scanning and made evaluator
  regex matching catch invalid manually supplied compiled programs.
- Expanded resource properties across accepted program size, argv/environment
  size, adverse ordered string predicates, cached folds, terminal templates,
  and audits. The matrix asserts the derived consumption bound, fixed compiled
  declaration bounds, one-time fold cache population, `O(PB)` trace output,
  and a practical 500 ms per-cell bound for the stated `O(PB²)` workload.

### GREEN

```text
bun test tests/policy-dsl-validate.test.ts tests/policy-dsl-evaluate.test.ts tests/policy-dsl-performance.test.ts tests/policy-cli.test.ts tests/policy-loader.test.ts tests/policy-config.test.ts
```

Output:

```text
55 pass
0 fail
19593 expect() calls
```

### Files

- Updated `src/policy/dsl/compile.ts`
- Updated `src/policy/dsl/evaluate.ts`
- Updated `src/policy/dsl/validate.ts`
- Updated `tests/policy-dsl-evaluate.test.ts`
- Updated `tests/policy-dsl-performance.test.ts`
- Updated `tests/policy-dsl-validate.test.ts`
- Updated this report

### Commit

Commit created immediately after this fix record: `fix(policy): harden DSL evaluator`.
