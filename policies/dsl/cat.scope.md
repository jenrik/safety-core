# `cat` policy scope

## Intent

Automatically permit GNU `cat` to read any operand path, while refusing to
treat Bash code named `cat` as that external program.

## Protected action and asset

The protected action is automatic authorization of one selected modeled `cat`
invocation. The protected boundary is immediate Bash command resolution: a
basename match must not authorize a local or inherited Bash function that
shadows GNU `cat`. File paths are deliberately not protected by this policy;
GNU `cat` may read any operand path supplied to it.

## In scope

This permission policy selects invocation events whose resolved executable
basename is exactly case-sensitive `cat`. It returns `allow` only if immediate
Bash lookup resolves the invocation to `external-path`.

All argv forms are in scope and equivalent to this policy. This includes GNU
`cat [OPTION]... [FILE]...` forms, zero or more file operands, `--`, repeated,
reordered, malformed, empty, unknown, or binding-derived arguments. File
operands may name any path. The policy does not parse options or operands.

Both an unqualified external `cat` and a path-qualified external executable
whose basename is `cat` are selected. `command cat` is also in scope when Bash
models its immediate target as `external-path`; it intentionally bypasses a
shell function and invokes the external command.

Prefix assignments, pipelines, standard-input producers, redirections, and
surrounding shell constructs are not restricted by this command's argv policy.
Every separately modeled command and every shell-owned file access retains its
own authorization decision. In particular, harness file permissions govern
redirection targets independently; this policy's file-operand allowance does
not authorize an attached shell redirection.

## Out of scope and threat-model exclusions

An invocation whose immediate target is `shell-function` is explicitly denied,
whether the `cat` function was declared locally in the Bash source or inherited
from the environment. The denial applies even if that function would eventually
invoke external `cat`, because this policy intentionally does not inspect or
authorize arbitrary Bash function bodies.

Selected invocations resolving to a Bash builtin or to an unresolved target
defer. Basenames other than exact lowercase `cat`, including `bat`, `cat.exe`,
and `catalog`, are not selected. Bash alias definitions and expansion are
outside scope because the analyzer does not model them; if expansion yields a
selected external `cat` invocation, that resulting event is assessed normally.

This policy does not validate GNU option syntax, inspect the bytes that `cat`
reads, restrict file paths, establish whether a file exists, or determine
command success. It does not authorize nested command substitutions, pipeline
peers, process substitutions, redirection effects, or other commands in the
source. Replacing a selected executable, manipulating `PATH`, or deliberately
bypassing this policy through another program is outside the non-adversarial
threat model.

## Assumptions and non-goals

The policy assumes that an external executable selected by basename `cat` is
GNU coreutils `cat` or a compatible implementation. Basename selection is an
operator-requested convenience, not proof of executable identity, provenance,
or integrity. The external-target check and explicit shell-function denial are
the complete modeled protection against Bash function shadowing.

This is not a file-path allowlist, content-validation, output-size,
environment, pipeline, or process-sandboxing policy. It intentionally accepts
the risk that GNU `cat` reads arbitrary operand paths.

## Expected outcomes

- **permit:** every selected event with immediate target `external-path`
  returns `allow`, regardless of arguments, file operands, or invocation
  context. A full request is automatically allowed only when all other modeled
  commands and file-access checks also allow and no guard denies it.
- **defer:** selected events whose target is a builtin or unresolved return
  `defer`; unselected basenames receive no decision from this policy. Harness
  prompts, unknown file checks, and independent nested-command decisions can
  also prevent final automatic approval.
- **deny:** a selected event whose immediate target is `shell-function` returns
  `deny` with guidance to invoke external GNU `cat` (for example, `command
  cat`) or remove the function. This denial dominates any permit from another
  policy for the same event.
