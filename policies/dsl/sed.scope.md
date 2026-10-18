# `sed` policy scope

## Intent

Permit routine, bounded line extraction with GNU `sed` without prompting. It is safe for this policy to disclose arbitrary readable files because the operator explicitly accepts that disclosure boundary.

## Tool identity and version

The CLI is GNU `sed`, the implementation maintained by the [GNU sed project](https://git.savannah.gnu.org/cgit/sed.git), not BusyBox sed, BSD sed, or a same-named vendored executable. The grammar is designed and tested against GNU sed 4.9, pinned to upstream tag `v4.9` commit `931f5b8013855d5305b46ec4d9988fbaefc8b83d` and the co-located capture `sed.gnu-4.9.help.txt` (SHA-256 `f1dd02ab934d009bae30d97a1e8e57548a5f3faccc12dfb553da4375817c180c`). GNU sed 4.8 is the immediate predecessor; no known 4.8-to-4.9 breaking change affects this grammar. On upgrade, resolve and record the replacement upstream tag commit, capture and diff `sed --help`, record its digest, and re-run this suite. A known or future release changing accepted option parsing or the authorized program grammar is out of scope until re-pinned and re-reviewed.

This scope covers GNU sed 4.9 and compatible later releases only; a grammar-affecting breaking release requires re-pin and review.

## Protected action and asset

This is a `permission` policy for automatic authorization of a selected sed invocation. It protects against authorizing scripts, options, extra operands, or function-shadowed executables beyond the exact read grammar. It deliberately permits reading any file path and accepts GNU sed stdout output. Shell redirection writes are persistent side effects deliberately admitted by the command envelope, but every shell-owned read/write remains subject to separate harness file permissions.

## In scope

The selector is the exact, case-sensitive `basename` `sed`; `isDirectExecutable("sed")` requires the unqualified spelling, and immediate resolution must be `external-path`. Bash functions, including inherited exported functions, do not inherit this permission. `command sed` may produce a separately modeled sed child; this policy only evaluates that child. Basename matching is the accepted identity tier; a same-named replacement or PATH manipulation is an operator-accepted assumption. No `environmentIndependent` opt-in is used, so unresolved execution never authorizes.

The complete argv grammar has exactly one quiet option (`-n`, `--quiet`, or `--silent`) and optionally one separate-files option (`-s` or `--separate`), in either order but both before PROGRAM. PROGRAM is exactly `Np` or `N,Mp`, with each N a nonzero ASCII decimal integer without a leading zero and lowercase `p`; numeric ordering is not validated. One or more statically known, nonempty file operands are required. Before an explicit `--`, each file must not begin with `-`; after it, every nonempty file except literal `-` is accepted. The policy recognizes known-good combinations only; GNU sed rejects invalid paths or runtime errors.

The three quiet spellings are exact synonyms, as are `-s`/`--separate`; attached, clustered, equals-value, repeated, or post-program forms are not synonyms. Options are not order-free. `LC_ALL`, the standard finite `LC_*` assignment names listed in the policy, and `POSIXLY_CORRECT` are permitted prefix assignments; inherited environment values are unrestricted and other prefix assignments defer. `POSIXLY_CORRECT` is deliberately not a decision gate: GNU sed's changed treatment of `--` can add a literal `--` file, but arbitrary multiple file reads are accepted. The conservative pre-`--` non-dash filename rule prevents normal GNU option permutation from reclassifying an operand as an option; it also accepts the known-POSIX false positive of deferring a safe hyphen-prefixed filename without `--`. No environment value is otherwise inspected. Transparent wrappers, including command substitution and `command`, are deconstructed by the engine: this policy authorizes only the sed child and wrappers/outer commands require their own authorization.

All inspected quiet options, separate options, PROGRAM bytes, and file operands must be statically known; unknown or binding-derived words defer. No folds are required: argv is structurally consumed, assignments use `assignmentsAreSubset`, and redirects are deliberately not inspected. All modeled shell redirections, descriptors, paths, here-strings, pipelines, process substitutions, and command-substitution context are admitted by this policy; their commands and file accesses are separately evaluated. Here-documents and unsupported descriptor operations produce an execution gap and therefore conservatively defer; this accepted over-deferral is recorded in `docs/policy-dsl.md` (redirect limitations) and `docs/known-bugs.md` (redirect/input authorization boundary).

## Out of scope and threat-model exclusions

Every nonmatching form defers: path-qualified or differently cased executables; builtin, function, or unresolved targets; assignments outside the finite locale/`POSIXLY_CORRECT` list; missing/empty/dynamic file operands; stdin `-` or omitted file; any other option; repeated quiet or separate options; post-program options; and scripts containing whitespace, `$`, zero or leading-zero addresses, regex addresses, semicolons, or any command besides the two numeric print forms. There is no deny rule.

Future flags or grammar additions fail closed because the finite grammar permits only from EOF `end` terminals after all operands have been structurally consumed; they require re-pin and re-review. The accepted false positive is here-document/unsupported-descriptor deferral. Deliberate bypass through another executable or transport, executable replacement, and PATH manipulation are outside the non-adversarial threat model.

## Assumptions and non-goals

The policy relies on the Bash walker preserving argv words, direct-executable identity, immediate execution targets, prefix-assignment names, redirects, and nested commands as documented in `docs/policy-dsl.md`. It does not establish file existence, file contents, sed success, output size, output destination safety, or wrapper/peer authorization. Harness file checks remain required: command `allow` is final only when every modeled file-access and other event allows. The redirect/input and here-document limitations are recorded in `docs/known-bugs.md`.

CLI evidence must enumerate the sed invocation for permit and defer examples; a redirection example must also enumerate its owned file-access event. Command substitution/pipeline examples need only establish the sed child and aggregate result; outer-wrapper and pipeline-peer identity are intentionally outside this policy's scope. The co-located suite uses `policyTestForFile`, which directly exercises the equivalent core policy-loading and analysis functions rather than spawning the CLI. Its reproducible evidence unit asserts the loaded canonical source and digest plus the representative allow/defer source outcomes; sanitized packaged-CLI commands remain complementary development evidence. Property tests vary quiet spelling, optional separate spelling and position, one-address/two-address programs, multiple operands, and the `--` form. A bounded adversarial argv-corpus property independently recognizes only the declared grammar, so sampled malformed options, program bytes, and operands fail closed; it is not a proof over arbitrary byte strings or lengths.

The unbounded-file-operand safety argument is structural. **Base:** after one accepted first file, the machine is in `filesBeforeTerminator` or `filesAfterTerminator`, and the external/direct/assignment predicates have already been proven. **Induction:** each additional pre-terminator operand must be nonempty and not begin `-`, then returns to `filesBeforeTerminator`; `--` changes only to `filesAfterTerminator`; each post-terminator operand must be nonempty and not equal `-`, then returns to `filesAfterTerminator`. Thus every additional operand is checked by the same invariant-preserving transition; an option-shaped, empty, or stdin operand cannot reach an allow terminal at any length. The DCRM validator proves every loop consumes input and terminates. This establishes the grammar's arbitrary-length file-list property from the state-machine structure, while the finite property suite regression-tests representative transitions.

## Expected outcomes

- **permit:** a direct, external GNU sed 4.9 basename invocation with exactly one pre-program quiet synonym, an exact `Np`/`N,Mp` script, and one static nonempty non-`-` file operand (optionally after `--`), provided every other modeled event and file-access check also allows.
- **defer:** every non-grammar form, unresolved/function/builtin target, unapproved prefix assignment, and engine execution gap; no policy authorization carries a reason and the native harness prompts.
- **deny:** this policy declares no deny rule. Independent guards and file checks may still deny.
