# Known Limitations

## Command arguments do not declare harness-authorized file accesses

Shell-redirect authorization is limited to file accesses
expressed through shell redirection syntax. It does not extract files or
directories from command arguments for authorization against the harness.
For example:

```sh
kubectl apply -f trusted.yaml
```

A command policy may be configured to accept this argument form, but that
acceptance does not establish that the harness authorized reading
`trusted.yaml`. Likewise, approval of a command does not establish harness
authorization for files it modifies through arguments, configuration, or
implicit behavior. Shell-redirect authorization is not general filesystem
mediation or a sandbox.

This is an explicit scope exclusion for the current redirect work, not a
reason to suppress modeled shell redirects. For example,
`kubectl apply -f - < trusted.yaml` does express a shell file read and falls
within that work.

### Possible future extension: policy-declared file and directory effects

In future, policies could emit a structured list of files and/or directories
that the accepted command is expected to modify. The core could forward those
declarations to the existing harness file-modification permission framework.
Read-access declarations could be considered separately, including inputs
such as `kubectl apply -f trusted.yaml`.

This extension is not implemented or committed to by the current design.
Before adoption, it needs defined path-resolution, directory-coverage, and
unknown-effect semantics. Declarations must not themselves grant file
permission: a harness `ask` must retain `defer`, and a harness `deny` must
block. Whether a list is exhaustive must be explicit; an expected-effects
list is not proof that a command cannot touch other paths.

Path-based command trust also assumes the referenced contents are trusted;
a readable or agent-writable file is not automatically a trusted command
input merely because its name is allowlisted.

## Unsupported shell redirect and directory facts defer

Here-document content and unsupported descriptor operations produce execution
gaps. The current grammar rejects some valid Bash forms, including read/write
`<>` redirects, some descriptor closures, assignment-only commands with output
redirects, and here-strings attached to certain compound statements. Those
sources cannot automatically authorize; parse-failure events retain `defer`.
Unproved directory-changing builtins invalidate the modeled cwd, so subsequent
relative file accesses defer rather than using the startup directory.

File contents, command-substitution output, and pipeline data are not fetched
or executed during authorization. Unsupported ANSI-C here-string escapes and
byte sequences not representable by the current string model remain unknown.
`/dev/null` is a supported file-permission target with no exemption: reads need
harness read permission, and writes/appends need modification permission.
Other special filesystem destinations currently defer as unsupported effects.

## OpenCode permission inspection requires resolved native context

The OpenCode adapters inspect compiled agent rules from read-only SDK endpoints,
identify the originating assistant agent through the tool call ID, and append
session-specific rules. Native `read`/`edit` resources are worktree-relative;
external-directory resources use the lexical target's directory wildcard.
File authorization uses lexical paths without inspecting filesystem metadata
or resolving symlinks. Resolving a target during preflight would provide only a
point-in-time observation, not proof that the later shell open uses that target.
This is a path-permission policy, not race-free target binding or symlink
containment enforcement. A `/` worktree remains the native relative-resource
base but does not make every path internal. Configured `ask` remains `defer`;
the bridge does not manufacture saved approvals or create native requests to
discover a permission result.

Missing tool-call identity, unavailable SDK endpoints, unrecognized permission
response shapes, or unknown lexical paths retain `defer`. Hosts can
instead inject a prompt-free `HarnessFilePermissions` implementation through
the adapter's `filePermissions` dependency. The v2 adapter currently uses the
legacy plugin-hook surface; modern action/resource/effect rulesets are not
interpreted as legacy permission/pattern/action rules.

The total command verdict and every file verdict are stored in the exact
tool-call generation record and reduced as `deny` > `defer` > `allow`. File `ask`
maps to `defer`; a native Bash denial is never weakened. With a valid preflight
record, combined `defer` maps to the existing whole-request Bash `ask` flow,
including when the initial native status is `allow`. No separate file approval
request is created.

Unseen call identities retain native status. Observed pending, invalidated, or
ambiguous generations instead require Bash `ask` even when native status starts
as `allow`; native `deny` remains a veto. Those observations never auto-approve
permission events. Reduced native command patterns are not re-analyzed as if
they were complete source.

Call identity locates a record but does not prove which retry a terminal callback
belongs to. The adapters associate each preflight with the actual arguments
object passed through the native before/after hooks, using an opaque identity
without adding fields to tool input. A per-call ledger retains every outstanding
generation, including older generations whose file checks are still pending.
Only a matching generation can retire its own record; it cannot retire older
or newer executions. Overlap remains restrictive until every known generation
is retired, regardless of completion or retirement order. Cloned or missing
terminal input, overlapping call-ID reuse, or recycling an arguments object for
the same call identity is ambiguous and retains `ask` rather than guessing which
generation to authorize.

Uncorrelated terminal events and invalidation drop cached source/evaluation
evidence while retaining a minimal restrictive lifecycle marker. Late completion
cannot revive an allow; a known denial in any outstanding generation is not
weakened. Correlated completion retires only its generation, and session deletion
retires that session's entire ledger. Every reload attempt invalidates observed
records, and a successful reload cannot revive a previous runtime's generation.
