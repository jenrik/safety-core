# Bash builtin policy design

## Status

This is an inventory and design record. The reviewed status and predicate
policies live beside it; each has its own co-located scope document. Commands
not expressly covered by those approved scopes remain unreviewed.

Each future policy must be narrow and must be created together with a
co-located `<policy_name>.scope.md`. The scope document must name the protected
action, exact in-scope forms, out-of-scope forms and threat-model exclusions,
assumptions/non-goals, and its `permit`, `defer`, and `deny` outcomes.

## Execution model

The shell execution tool starts a separate Bash process for each tool call.
Therefore variables, functions, aliases, traps, options, working directory,
directory stack, and job state created by one tool call do not transfer to the
next call.

Those state changes can nevertheless affect commands later in the **same Bash
source**. For example, `cd dir; command`, `export NAME=value; command`, and
`f() { command; }; f` have to be reasoned about as one modeled source. Host
effects that outlive a shell process--such as filesystem writes, spawned
processes, history-file modifications, and signals sent to another process--do
not become safe merely because the next tool call has a new shell.

Policies must classify structural command events rather than source prefixes.
The expected direct-builtin proof for an eventual permit normally includes an
unqualified direct spelling, immediate lookup as a Bash builtin rather than a
function or external executable, statically resolved relevant arguments, and
an exact argument grammar. Alias expansion is expected to occur before the
builtin invocation event is classified; spelling aliases that remain as
distinct builtins are listed below.

## Redirections and file authorization

Redirection file opens are enforced independently by the harness file
permission system. A command-level policy need not reject an otherwise
acceptable builtin merely because it has a supported input or output
redirection.

For example, a future output policy may cover `echo foo > ./some-file.txt` or
`printf '%s\n' foo >> log.txt`. Its command-level permit is not a final file
authorization: every modeled owned file access remains subject to harness
permission checks. A harness denial wins; a prompt/unknown result remains
deferred. The policy must not claim that it authorizes the redirected path.

Redirected *code* and redirected data that alters subsequent shell behavior
remain separate command-semantic concerns. In particular, `source file`,
`eval`, `read`, and `mapfile` require review beyond the fact that an input file
open is harness-authorized.

## Design constraints

- Use the DCRM Bash policy DSL only; DSL-to-native-code escapes are not in
  scope without explicit human approval.
- Keep each policy focused on one protected action. Do not create a single
  all-builtin allow policy.
- Cover natural, non-adversarial variants claimed by a scope: aliases,
  supported flag forms, and relevant argument ordering.
- Do not model attempts to bypass a policy using unrelated external commands
  as part of this policy family's threat model.
- For every approved `permit`, `defer`, and `deny`, create a non-secret,
  explicit configuration; run `safety-core validate` before and after changes;
  record its canonical source paths and digests; and use a sanitized
  environment for `safety-core explain --json` evidence.
- Review modeled events as well as final decisions. CLI evidence complements
  direct and property tests; it does not replace them.
- Before finalizing a policy, submit it, its scope document, relevant
  implementation, CLI evidence, and test evidence to the required adversarial
  reviewer. Present all findings to the operator and do not revise findings
  without explicit direction.

## Inventory baseline

The target is the current installed Bash builtin inventory, not shell grammar
or reserved words. The baseline was collected from Bash `5.3.15(1)-release`
with a clean non-interactive shell using `enable -a`; it contains 57 enabled
builtins. The exact inventory is installation-sensitive and must be rechecked
if Bash is upgraded or rebuilt.

Excluded grammar / reserved constructs include `!`, `(( ... ))`, `[[ ... ]]`,
`case`, `coproc`, `for`, `function`, `if`, `select`, `time`, `until`, `while`,
and `{ ...; }`. They are not builtin-executable invocation events and need a
separate parser/source-level design if they need policy coverage.

The installed shell does not expose optional programmable-completion builtins
such as `bind`, `compgen`, `complete`, or `compopt`; they are not in this
inventory. A future inventory refresh must add them only after reviewing their
actual installed behavior.

## Commands awaiting review

All entries below are **unreviewed**. The proposed family is only a review
queue; it is not an authorization decision.

### First review queue: predicate and status builtins

The operator selected `:`, `true`, `false`, `test`, and `[` for first review.
They are approved for narrowly scoped automatic authorization. `bash-status`
covers direct `:`, `true`, and `false`; `bash-test` covers direct `test` and
bracket-terminated `[`. Their precise permit/defer behavior is defined by the
respective scope documents.

- `:`, `true`, and `false` do not have command-specific host effects, but
  attached redirections remain independently checked by the harness.
- `test` and `[` evaluate expressions and can inspect shell values and
  filesystem metadata. Their expression grammar, argument boundaries, and any
  metadata-query implications must be reviewed before a policy permits them.
- `[` is the spelling alias of `test` but requires a final `]` operand. A
  future scope must prove this structural distinction rather than treating the
  two spellings as prefix-equivalent.
- The execution-model question for `test` and `[` remains recorded in
  [`docs/future-work.md`](../../../docs/future-work.md). The initial policy
  permits statically resolved predicates while that structural investigation is
  completed and must be revisited if its result changes modeled evidence.

| Builtin | Proposed review family | Notes for review |
| --- | --- | --- |
| `.` | source evaluation | Alias spelling with `source`; evaluates file content. |
| `:` | no-op / status | Redirections may independently open files. |
| `[` | predicate | Alias spelling with `test`; require its closing `]`. |
| `alias` | shell-state inspection/mutation | Listing/querying versus defining aliases. |
| `bg` | job/process control | Resumes a stopped job. |
| `break` | control flow | Affects a surrounding loop in the same source. |
| `builtin` | builtin dispatch | Can invoke another builtin; needs nested-command semantics. |
| `caller` | inspection | Reports call-stack information. |
| `cd` | shell-state mutation | Changes cwd for later commands in the same source. |
| `command` | discovery / dispatch | Lookup forms differ from command-execution forms. |
| `continue` | control flow | Affects a surrounding loop in the same source. |
| `declare` | variable mutation/inspection | Similar but not identical to `typeset`; `-p` is inspection. |
| `dirs` | directory-stack inspection/mutation | `-c` clears the stack. |
| `disown` | job/process control | Removes or marks jobs. |
| `echo` | output | Output destinations are independently file-authorized. |
| `enable` | builtin availability | Enables/disables or dynamically loads builtins. |
| `eval` | source evaluation | Parses/evaluates constructed shell source. |
| `exec` | process / descriptor control | Replaces the shell or changes descriptors. |
| `exit` | control flow | Terminates the current shell. |
| `export` | environment mutation/inspection | `-p` is inspection; other forms alter child environment. |
| `false` | no-op / status | Produces failure status. |
| `fc` | history / execution | Can edit, list, or execute history commands. |
| `fg` | job/process control | Foregrounds a job. |
| `getopts` | variable mutation | Advances option state and writes variables. |
| `hash` | command-cache inspection/mutation | Lookup/listing differs from cache changes. |
| `help` | discovery | Displays builtin help. |
| `history` | history / file I/O | Listing, deletion, and file operations differ. |
| `jobs` | job inspection | Lists job state. |
| `kill` | job/process control | Sends a signal to a job or process. |
| `let` | variable mutation | Evaluates arithmetic and writes shell variables. |
| `local` | variable mutation | Creates/modifies function-local variables. |
| `logout` | control flow | Terminates a login shell. |
| `mapfile` | input / variable mutation | Alias spelling with `readarray`; reads into arrays. |
| `popd` | directory-stack mutation | Changes directory stack and usually cwd. |
| `printf` | output / variable mutation | `-v` writes a variable; other forms emit output. |
| `pushd` | directory-stack mutation | Changes directory stack and usually cwd. |
| `pwd` | inspection | Reports cwd. |
| `read` | input / variable mutation | Reads input and writes variables. |
| `readarray` | input / variable mutation | Alias spelling with `mapfile`; reads into arrays. |
| `readonly` | variable mutation/inspection | `-p` is inspection; other forms permanently mark variables. |
| `return` | control flow | Returns from a function or sourced script. |
| `set` | shell-state / positional parameters | Inspects or changes shell options and positional parameters. |
| `shift` | positional-parameter mutation | Changes later argument interpretation in the same source. |
| `shopt` | shell-option inspection/mutation | `-p`/`-q` differ from `-s`/`-u`. |
| `source` | source evaluation | Alias spelling with `.`; evaluates file content. |
| `suspend` | job/process control | Suspends the current shell. |
| `test` | predicate | Alias spelling with `[`; supports unary/binary expressions. |
| `times` | inspection | Reports process accounting data. |
| `trap` | handler inspection/mutation | Installing a handler can cause future code evaluation. |
| `true` | no-op / status | Produces success status. |
| `type` | discovery | Reports command resolution. |
| `typeset` | variable mutation/inspection | Similar but not identical to `declare`; `-p` is inspection. |
| `ulimit` | resource-limit inspection/mutation | Query forms differ from limit changes. |
| `umask` | permission-mask inspection/mutation | Query forms differ from mask changes. |
| `unalias` | shell-state mutation | Removes aliases. |
| `unset` | variable/function mutation | Removes variables, array members, or functions. |
| `wait` | job/process control | Waits for jobs/processes; `-p` can write a variable. |

## Candidate policy families to decide after review

1. **Predicate and status:** exact `:`, `true`, `false`, `test`, and `[` forms.
2. **Command discovery:** read-only lookup forms of `command`, `type`, `help`,
   and `caller`.
3. **Output:** `echo` and non-`-v` `printf`, including supported redirects whose
   file effects stay under harness authorization.
4. **Shell-state inspection:** narrowly selected query/list forms such as
   `pwd`, `times`, `jobs`, and option-specific inspection modes.
5. **Source evaluation and dispatch:** `.`, `source`, `eval`, `builtin`, and
   executable forms of `command`.
6. **Shell-state mutation:** directory, variable, environment, option, alias,
   trap, and resource-limit mutation.
7. **Control flow and process control:** loop/function/shell termination and
   job/signal operations.
8. **History and input:** `fc`, `history`, `read`, `mapfile`, and `readarray`.

The next design step is to review each row's exact permit/defer/deny intent and
natural forms before creating any policy artifact.
