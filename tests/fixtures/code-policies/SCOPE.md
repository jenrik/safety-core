# Strict Read-Only Fixture Scope

`strict-read-only.policy.ts` is the trusted native fixture for ordinary strict
read-only commands. It deliberately does not implement the declarative kubectl
dry-run apply permission grammar.

## Intent And Protected Action

The protected action is persistent Kubernetes API mutation and the protected
asset is target-cluster state. The fixture remains conservative: `kubectl apply`
including every dry-run form defers. The generated
`policies/dsl/strict-kubectl.policy.json` alone owns the narrow operator-approved
dry-run authorization, and direct tests compare those intentionally different
outcomes rather than treating them as parity failures.

## Scope And Outcomes

The fixture permits the existing strict read-only command inventory, subject to
known arguments, a bare executable, no assignments or redirects, no inherited
executable function, and safe configured environments. For kubectl it continues
to defer protected ordinary reads and all unreviewed commands. The separate
guard fixture owns `kubectl view-secret` denial.

No fixture rule permits `kubectl apply`, `apply set-last-applied`,
`edit-last-applied`, `view-last-applied`, a missing input, an option terminator,
or any dry-run option syntax. Transparent wrappers are conservatively deferred
by the native command route; assignments, redirects, path-qualified executables,
and unsafe `KUBECONFIG` also defer. The fixture does not inspect manifests,
validate server-side dry-run, or execute/sandbox kustomize plugins; the DSL
policy's `-k` plugin exemption is outside this fixture.

For the DSL's apply grammar, `-f`/`--filename` accepts a syntactically nonempty
file, directory, URL, or stdin (`-`); existence and content validity are out of
scope. The Bash engine resolves bindings established by prior shell commands
before policy evaluation, so the DSL may allow resolved executable, dry-run, and
source values. Unresolved bindings defer, and leading assignments on the
invocation still defer. This fixture nevertheless defers every `kubectl apply`
form independently of those resolved values.

## Assumptions And Threat Model

This fixture is intentionally independent of the native kubectl dry-run helper
and of the declarative policy implementation so it cannot mask DSL faults.
Semantic validity, Kubernetes authorization, and attempts to evade policy with
unrelated tools are outside the non-adversarial threat model.
