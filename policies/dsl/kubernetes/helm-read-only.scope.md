# Helm Read-only DSL Policy Scope

## Intent and protected action

`helm-read-only.policy.json` permits a minimal Helm 4.3.0 read-only subset.
It protects Kubernetes persistence and local files from Helm mutations,
dependency writes, post-renderer execution, and output-file writes. Helm's own
chart and provenance cache writes during an allowed remote read are a deliberate
persistent exception. It is not a
chart, values-file, repository, release-name, or Kubernetes authorization
validator.

## Exact in-scope commands

The policy evaluates a projected `helm` invocation regardless of its provenance
(for example, a Helm child of `env helm …`, `sh -c`, or `eval`). It does not
authorize the complete wrapper request; wrapper invocations and execution gaps
are deliberately deferred to other policies. Helm events require known command
paths and positional arguments, no invocation assignments or redirects, no inherited `helm`
function, and no nonempty/unknown `KUBECONFIG` or `HELM_KUBETOKEN`.

| Command | Permitted flags |
| --- | --- |
| `--help`, `--version`, `env`, `help [TOPIC ...]` | none |
| `version` | `--short` |
| `completion {bash|fish|powershell|zsh}` | none |
| `repo {list|ls}` | `--output table`, `-o table`, `-otable` |
| `{list|ls}` | `--namespace`/`-n`, `--output table`, `-o table`, `-otable`, `--all-namespaces`/`-A`, `--deployed`, `--failed`, `--pending`, `--superseded`, `--uninstalled`, `--uninstalling` |
| `{history|hist} RELEASE` | `--namespace`/`-n`, `--output table`, `-o table`, `-otable`, `--show-rollback-revision` |
| `{show|inspect} chart CHART` | `--version`, `--repo`, `--devel`, `--insecure-skip-tls-verify`, `--plain-http`, `--verify` |
| `search hub [KEYWORD]` | `--output table`, `-o table`, `-otable` |
| `search repo [KEYWORD]` | `--output table`, `-o table`, `-otable`, `--devel`, `--versions`/`-l` |
| `verify PATH` | none |
| `lint CHART` | `--values`/`-f`, `--set`, `--set-file`, `--set-json`, `--set-literal`, `--set-string`, `--quiet`, `--strict`, `--skip-schema-validation`, `--with-subcharts` |
| `template [NAME] CHART` | the lint value flags; `--dry-run={client,server}`, `--version`, `--repo`, `--devel`, `--insecure-skip-tls-verify`, `--plain-http`, `--verify`, `--api-versions`/`-a`, `--show-only`/`-s`, `--include-crds`, `--no-hooks`, `--skip-crds`, `--skip-tests` |

Documented separate, equals-long, attached-short, and short-cluster forms are
accepted only where declared; `-Aotable` is an accepted cluster example. Remote reads (including their Helm-managed cache
writes) and server dry-run are trusted. Values inputs are accepted under the
non-adversarial assumption that values files do not contain secret material;
deployments should reference externally managed Secrets instead. Helm owns value
syntax and command-success validation: a required option value may be empty,
unresolved, or look like a switch, and this policy does not reject it solely
because Helm later returns a non-zero exit status. The policy only requires a
known option value where it constrains that value: the `table` output mode and
`--dry-run={client,server}`.

## Exclusions and outcomes

Every other Helm command or flag defers, including install, upgrade, uninstall,
rollback, repo add/update, dependency build/update, pull, package, push,
registry and plugin actions, `status`, all `get` children, `--keyring`,
`--output-dir`, `--dependency-update`, and `--post-renderer`. `status` and
`get` are excluded because they disclose notes, resources, values, manifests,
hooks, or release metadata. Extra operands, standalone unknown options, and
`--` defer. An excluded-looking token used as the value of an allowed option is
not a standalone flag and is therefore delegated to Helm's parser.

`permit` applies only to the complete forms above. `defer` applies to every
excluded or incomplete form for human approval. This permission policy never
returns `deny`; another loaded guard may deny the complete request. Attempts to
bypass through another executable or bespoke transport are outside the
non-adversarial threat model.
