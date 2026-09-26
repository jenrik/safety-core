# Kubectl DSL Policy Scope

`kubectl.policy.json` is the guard policy for secret-related commands. This
document describes the separate `strict-kubectl.policy.json` permission policy.

## Intent And Protected Action

The policy permits a narrow, non-persistent Kubernetes apply preview. The
protected action is creating, changing, or deleting Kubernetes API resources;
the protected asset is the target cluster's persistent state. This is a
permission policy, not a manifest validator or a credential/secret reader.

## Tested Version And In-Scope Grammar

The inventory is pinned to the installed and tested `kubectl v1.37.0`
(`kustomize v5.8.1`). It permits only this ordinary grammar. The documented
value-form apply options, `--dry-run=(client|server)`, and global selectors may
appear before or after `apply` where kubectl v1.37.0 accepts them. Apply-local
bare/no-value flags may appear only after `apply`:

```
kubectl [approved options] apply [approved options] --dry-run=(client|server) (-f INPUT | -k DIRECTORY)
```

Exactly one successfully parsed `--dry-run=client` or `--dry-run=server` is
required. The spelling and value are case-sensitive. `-f`/`--filename` accepts
a syntactically nonempty file, directory, URL, or stdin (`-`); existence and
content validity are out of scope. `-k`/`--kustomize` accepts a nonempty
directory. Multiple `-f` values are allowed, but `-k` cannot be combined with
`-f` or `-R`/`--recursive`.

The v1.37.0 approved apply inventory is: `--all`,
`--allow-missing-template-keys`, `--cascade={background,foreground,orphan}`,
`--field-manager`, `--force`, `--force-conflicts`, `--grace-period`,
`--openapi-patch`, `--overwrite`, `--prune`, `--prune-allowlist`,
`-R`/`--recursive`, `--request-timeout`, `--selector`/`-l`, `--server-side`,
`--show-managed-fields`, `--subresource`, `--timeout`, `--validate`, and
`--wait`; the reviewed request selectors are `--context` and
`--namespace`/`-n`. The policy permits their documented bare boolean spellings
only after `apply`, and `--validate` only as its documented post-`apply`
no-value form. Consequently,
explicit boolean assignments such as `--force=false` defer even though kubectl
can parse them; this is a deliberate narrow scope, preventing malformed values
from being mistaken for valid ones with the existing generic DSL constructs.

For v1.37.0's string flags, empty `--context=`, `--namespace=`,
`--field-manager=`, `--selector=`, `--subresource=`, and
`--prune-allowlist=` are accepted syntax and are intentionally preserved. Empty
source inputs, empty `--cascade`, and empty `--validate` are not permitted.
`-Rfmanifest.yaml` is a supported short cluster form. The policy intentionally
does not approve `--output`/templates, cache/profile/log-output switches, or
credential, server, proxy, TLS, and impersonation routing flags.

`-k` is an explicit kustomize-plugin exemption: plugins are not inspected or
sandboxed. A server-side dry-run is trusted to honor Kubernetes' non-persistence
guarantee for this narrowly approved request.

## Permit, Defer, And Deny

The policy allows only the complete grammar above, with a direct executable,
known arguments, no leading shell assignments, no redirects, no inherited
`kubectl` function, and no nonempty or unknown `KUBECONFIG`. Bindings resolved
by a prior shell command are in scope: the Bash engine resolves their executable
and argument values before DSL evaluation. Unresolved executable or argument
bindings defer, and leading assignments on the invocation still defer. The
policy also defers transparent wrappers and commands reached through `eval`,
shell-command, or binding-derived-script provenance. These conditions are
evaluated by the DSL; the reverted native strict profile remains conservative
and defers dry-run applies.

It defers missing inputs, `apply` child commands such as `set-last-applied`,
arbitrary positional operands, `--`, unknown flags, malformed or duplicate
dry-run options, mixed-case dry-run values, conflicting source forms, invalid
cascade values, explicit boolean values, and every unreviewed option. It does
not deny an apply preview. The separate guard policy denies `kubectl
view-secret` and defers protected ordinary reads.

## Out Of Scope And Threat Model

Persistent applies, client/plugin behavior, manifest existence and validity,
plugin execution, target-cluster authorization, and semantic validation are out
of scope. The policy relies on kubectl v1.37.0 parsing and, for server dry-run,
on the selected API server. Deliberate attempts to bypass the policy through
unrelated executables or bespoke transport calls are outside the non-adversarial
agent threat model.
