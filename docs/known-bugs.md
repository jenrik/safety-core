# Known Bugs

## Executable-basename selectors cannot also exclude shell-function declarations

Permission-policy selection currently distinguishes an invocation by its modeled
executable basename, but it cannot express a single selector that both matches
basename `env` and independently excludes or classifies a same-named Bash
function declaration. A local or imported `env` function is modeled as a
`shadowed-env-function` execution gap rather than as an external `env`
invocation.

Consequently, basename-scoped policies such as `env-command` must select only
the external invocation event and rely on the aggregate execution-gap behavior
to defer a shadowed function call. They must not combine executable and
execution-gap selectors to try to classify both cases: the runtime's
executable-selector prefilter admits invocation events only, so that mixed
selector form does not evaluate the execution-gap branch. This is conservative
today because execution gaps independently defer, but policy-specific audit
traces cannot distinguish that defer.

A future selector/runtime design should preserve OR semantics across executable
and non-invocation selector kinds, or provide an explicit predicate for an
external (non-function) execution target. Until then, policies should document
this boundary and keep their selector limited to the invocation form they
authorize.

## Eventless shell builtin work can be omitted from policy coverage

The policy event stream records modeled command invocations and execution gaps,
but some reachable shell work produces neither. A call to a locally defined
shell function whose body contains only eventless builtins can be omitted from
the stream while analysis is still reported complete.

Consequently, an otherwise covered command in the same Bash source can receive
an `allow` decision even when preceding omitted work can truncate or create a
file, mutate shell state, or shadow a later command. For example, a policy that
permits `command -v helm` can encounter a local `command` function that prevents
the lookup from being modeled as the direct builtin invocation.

The core must represent such work as policy-visible invocations or execution
gaps, or mark the analysis incomplete until it has independent coverage. Add
source-level regressions and properties for local-function bodies before
treating a zero-event or partially eventless
analysis as automatically safe.

The standalone-output-redirect part of this bug is resolved: `> output` now
produces an executable-less invocation and a harness file-modification
requirement. Without that permission check it defers, including when another
command in the same source is permitted. See
`tests/bash-redirect-authorization.test.ts`.

## Resolved: here-string redirections were not projected as redirects

The Bash analyzer can model an invocation with a here-string redirection as an
otherwise ordinary invocation with an empty `redirects` collection. For
example, a policy that rejects redirects with `hasRedirect()` can still allow
`jf rt ping <<<"payload"` when no other policy event requires a prompt.

Consequently, a policy's redirect check applies only to redirects represented
in its event. It does not prove that the Bash source contains no input
redirection or expansion routed through a here-string.

Here-strings are now projected as `here-string` redirects with separate inline
content, and appear in effective descriptor context. They do not appear as
filesystem paths. Their expanded content, including Bash's final newline, is
known or explicitly unknown. Parser/walker properties compare supported forms
with Bash; packaged-CLI regressions exercise `allow`, `defer`, and `deny` through
the scoped `tests/fixtures/redirect-input.policy.json` fixture. Existing
`hasRedirect()` checks now observe here-strings.

## Command-substitution assignment context can be omitted from nested invocation events

The Bash analyzer can model an invocation nested in a command substitution
without projecting its enclosing assignment context onto that invocation.
For example, a policy that rejects assignments on its invocation event can
still allow:

```sh
out=$(nix-prefetch-url https://example.test/source)
```

The nested `nix-prefetch-url` event currently has an empty `assignments` object,
despite the source-level command-substitution assignment. Consequently, a policy check over only the
modeled invocation cannot prove that the complete Bash source lacks these
effects. The core must propagate enclosing assignment contexts to nested events or emit an
execution gap that forces `defer`; until then, policies that rely on this proof
must explicitly declare the limitation out of scope.

The brace-group and subshell output-redirect part is resolved. Ordered enclosing
redirects and effective descriptor bindings propagate to child invocations;
the owning redirect event produces file-access requirements once, and temporary
bindings are restored on exit. Function redirects are evaluated at call time.

## Description-zero parsing

The Bash projection can mistake an explicit descriptor `0` for executable or
argument text without emitting an execution gap. This remains unresolved;
documenting it does not repair the parser.

For example:

```sh
0<<<accepted redirect-fixture
redirect-fixture <<<accepted 3<&0 0<&3
```

In the first form, Bash executes `redirect-fixture` with the here-string on
stdin, but the analyzer can report executable `0` and argument
`redirect-fixture`. In the second form, Bash passes no arguments, but the
analyzer can fabricate argument `0` while reporting complete analysis.

An argument-sensitive policy could therefore classify an argument or executable
that Bash does not actually use. Policies must not rely on exact executable/argv
proof for these descriptor-zero forms until the numeric descriptor boundary is
recovered structurally, or uncertainty produces an execution gap. A future fix
needs Bash-oracle properties for prefix/suffix placement, consecutive redirects,
duplication, and mixed input/output operators.

## Redirect and input authorization boundary

The implemented boundary is:

- The core models reachable supported shell redirects, including standalone
  redirects and redirects owned by builtins or compound commands. Unmodeled
  work remains an execution gap rather than disappearing from coverage.
- File-backed shell redirects use a core interface for checking the harness's
  file read/write permissions. Relative paths resolve against the execution
  working directory; the harness's workspace boundary remains a separate fact.
  Every file-open effect requires coverage, even if a later redirect replaces
  that descriptor's destination.
- In OpenCode, a file modification matching native `edit` permission `ask`
  contributes `defer`, not automatic approval or a separate interactive file
  approval request. `deny` blocks the request; `allow` satisfies only the file
  permission check and cannot override a command-policy denial. Applicable
  native `read` and `external_directory` checks must also be respected.
- Here-strings are command input, not user-file access requests. Policies have
  visibility into their expanded content or explicit unknown content, and may
  approve or defer based on whether that input affects the accepted command
  form. Modeling preserves Bash's appended newline and supported expansion semantics
  without executing substitutions to discover their output.
- Pipes and process substitutions, such as `foo | bar` and `foo <(bar)`, stay
  within command analysis: both `foo` and `bar` require invocation coverage.
  Their connection is not a harness file-permission request. Actual file
  redirects inside either command still require their own file checks.
- Command policies may condition approval on the effective input/output
  redirect context. For example, a configured policy may defer
  `kubectl apply -f -` with unknown input but accept it with an explicitly
  trusted file input redirect, subject to harness read permission. Trust in
  input for a command is distinct from permission to read that input.

The public core interface is `HarnessFilePermissions.check`; the asynchronous
`checkBashFilePermissions` step combines its results with the pure command-policy
decision. Offline evaluation exposes pending `fileAccesses` and defers. v2 DSL
descriptor predicates and input references are documented in
[Policy DSL](policy-dsl.md#redirects-descriptors-and-harness-file-permissions).

OpenCode stores the complete source, execution directory, aggregate command
verdict, and individual file verdicts in one preflight record per tool call.
The combined verdict is the most restrictive of the command and file verdicts:
`deny` wins over `defer`, which wins over `allow`. File `ask` maps to `defer`.
Native Bash denial remains a veto; combined `defer` uses the existing
whole-request Bash `ask` flow, not a separate file prompt. Automatic approval
requires a complete cached preflight record, never a reduced native command
pattern. Generations are correlated through opaque execution identity, and a
per-call ledger retains every outstanding generation. Overlapping retries and
uncorrelated terminal callbacks retain `ask` until every generation is retired.
Retiring a newer execution cannot erase an older pending file check, and a stale
completion cannot remove a newer generation. Invalidated records cannot
revive automatic approval. `/dev/null` has no permission exemption: its reads and writes require
the corresponding harness file checks.

Extracting file accesses from command arguments is outside this session's
scope. See [Known limitations](known-limitations.md) for that boundary and the
possible future policy-declared file/directory effects interface.
