# `cd` policy scope

## Intent

Permit the ordinary Bash `cd` builtin without a harness prompt so an agent can
navigate its working directory as part of normal task execution. Changing the
current directory is a routine, low-risk shell operation: it reads no protected
file and produces no persistent effect outside the invoking shell.

## Protected action and asset

The protected boundary is automatic authorization of the modeled `cd`
invocation. This policy must not authorize execution of anything other than the
direct, unqualified Bash `cd` builtin. It must not mint a permission that could
be inherited by a path-qualified spelling, an executable named `cd`, a shell
function named `cd`, or an invocation that carries a command-prefix assignment.

## In scope

The policy permits exactly an invocation with all of these properties:

- The executable spelling is the unqualified `cd` (`isDirectExecutable ["cd"]`),
  so the executable value is literally `cd`.
- The invocation carries no command-prefix assignments.
- The launcher is not a definite shell function (and no inherited exported
  function shadows the name).

Every argument is in scope: `cd /tmp`, `cd ..`, `cd ~`, `cd -`, `cd "/some
dir"`, and `cd "$HOME"` are all authorized. The argument is deliberately not
inspected, resolved, or constrained — the builtin itself decides whether a
target is valid, and an argument cannot cause `cd` to execute another command.
Statically resolved and unresolved arguments are treated identically.

## Out of scope and denied forms

The following do **not** receive this permission:

- **Path-qualified spellings defer.** `/bin/cd`, `/usr/bin/cd`, `./cd`, and
  `../cd` all share the basename `cd` and therefore select this policy, but they
  fail `isDirectExecutable ["cd"]` because their executable value is not
  literally `cd`. They fall through to the state default and `defer`, leaving
  any decision to the state's other policies or the harness prompt.
- **Function shadowing denies.** A local function named `cd` resolves to
  `executionTargetIs "shell-function"` and is denied with an actionable reason
  that steers the agent to `command cd`/`builtin cd` or to unset the function. A
  known inherited exported function (detected by `hasInheritedExecutableFunction
  ["cd"]`) is denied the same way. This is a denial rather than a defer because
  a shadowing function can silently change what a `cd` spelling executes, and
  the safe alternative is always available.
- **Command-prefix assignments defer.** A command-prefix assignment
  (`FOO=bar cd /tmp`) fails the envelope check on the allow case and falls
  through to the default `defer`. This policy does not broaden into environment
  mutation.
- **Redirections are not inspected by this policy.** The modeled invocation's
  `redirects` include redirect context shared with sibling invocations in the
  same list, so a redirect check here would also reject a plain `cd` in
  `cd <dir> && <command> 2>/dev/null`. Redirect *writes* are authorized
  independently by the aggregate request's file-access handling: `cd /tmp > out`
  still defers because the output redirection is not itself permitted, while the
  `cd` invocation is covered. This policy therefore does not gate on redirection
  and does not vouch for any redirect target.

The policy declares no other deny rule. Ordinary invocation forms of unrelated
commands, aliases, `pushd`/`popd`, and shell-specific `CDPATH` behavior are
outside this policy.

## Assumptions and non-goals

The Bash parser and walker provide a complete, resolved invocation event for the
stated form. This policy authorizes only the modeled direct Bash builtin; it is
not a general-authorization policy and does not vouch for the safety of a target
directory, its contents, or any later command run from it. It does not authorize
file reads, environment mutation, or terminal output handling.

Two existing core-modeling limitations are explicitly excluded from this
policy's scope and are tracked in [`docs/known-bugs.md`](../../docs/known-bugs.md):
complete environment snapshots do not currently normalize exported Bash
functions, and some standalone shell work can be absent from the policy event
stream. Accordingly, the function-shadowing and redirection checks apply to
facts carried by the invocation event; they do not prove that the entire Bash
source lacks those omitted effects.

## Expected outcomes

- **permit:** the exact in-scope shape above yields `allow` from this permission
  policy. The combined request is automatically allowed only when every other
  reachable invocation is also covered and no guard denies it.
- **defer:** every path-qualified spelling, every assignment-bearing invocation,
  and any other form outside the grammar yields `defer` from this policy and
  remains prompt-gated unless an independent policy covers that invocation.
- **deny:** a local or inherited Bash function shadowing `cd` yields `deny` with
  a reason directing the agent to `command cd`/`builtin cd` or to unset the
  function. Independent guard policies retain their normal dominant ability to
  deny an invocation; such a denial is outside this policy's authorization
  decision.
