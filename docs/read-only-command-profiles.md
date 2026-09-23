# Credential-safe read-only command profiles

These profiles are intentionally narrower than a "does not write" policy. An
auto-approved command must neither modify state nor expose credentials or other
arbitrary file, environment, database, workload, or container content. Every
unlisted command is deferred to the harness permission prompt.

## Generic profile

`readOnlyBash` is native harness permission data for commands whose whole
surface is metadata-only or side-effect free:

```text
ls pwd id lsof readlink realpath stat test which sleep wait true false
```

Content readers and transformers are deliberately excluded: `cat`, `head`,
`tail`, `grep`, `rg`, `jq`, `base64`, `sha256sum`, `strings`, and related tools
can disclose secret material even when they do not modify files. Filesystem
mutators, interpreters, and command runners are also excluded.

## Parsed profiles

The following opt-in Nix options use the shared parser and require one literal
standalone command. They reject explicit executable paths, leading environment
assignments, shell syntax, redirects, quoting, expansions, unknown flags, and
secret-shaped positional paths. Accepted options are command-specific;
`kubectl`/`oc -n/--namespace` and `--context`, and npm `--json` are representative examples. These options
may appear before or after command operands where their CLIs support it. Other
options remain prompt-gated because these tools commonly use them for
credentials, output files, configuration selection, execution, or local
mutation.

| Nix option | Executable | Approved command paths |
| --- | --- | --- |
| `ghReadOnly` | `gh` | All audited forms currently defer because common GitHub CLI startup can migrate configuration, check for updates, and launch telemetry before dispatch. `gh api` remains owned by `ghApiReadOnly`, and `gh pr create` remains owned by `ghPrCreate`. See the [exhaustive GitHub CLI 2.100.0 audit](./gh-read-only-command-audit.md). |
| `helmReadOnly` | `helm` | help/completion, search/chart metadata and documented aliases, verify, version; repository configuration, lint, and chart values/README/CRD contents are excluded because they can expose credentials or chart values |
| `argocdReadOnly` | `argocd` | account inspection, app/appset/cluster/repository/project lists, project role lists and the `project`/`proj` aliases, version |
| `cosignReadOnly` | `cosign` | tree, verify variants, version; environment output is excluded |
| `craneReadOnly` | `crane` | catalog, digest, ls, manifest, validate, version; image configuration is excluded |
| `dockerReadOnly` | `docker` | info, version, search, image/network/volume and other structural lists, plus system-df metadata; container lists are excluded because they display configured commands |
| `jfrogReadOnly` | `jf`, `jfrog` | config show, options, Artifactory search, stats, version |
| `kubectlReadOnly` | `kubectl` | API discovery, auth checks, context metadata, explain, non-secret get, plugin list, version |
| `nixReadOnly` | `nix` | hash, nar ls, path/store inspection, version, why-depends |
| `nixEnvReadOnly` | `nix-env` | exact version only; legacy operation flags require a dedicated parser |
| `nixStoreReadOnly` | `nix-store` | exact version only; legacy operation flags require a dedicated parser |
| `ocReadOnly` | `oc` | OpenShift equivalents of the restricted kubectl profile plus projects/whoami |
| `podmanReadOnly` | `podman` | info/version, structural lists and their documented aliases, diff/port, system metadata; container lists and image history are excluded |
| `podmanComposeReadOnly` | `podman-compose` | images, port, version; `ps` is excluded because it displays configured commands |
| `skopeoReadOnly` | `skopeo` | list-tags, manifest-digest, standalone-verify, version; image inspection is excluded |
| `tofuReadOnly` | `tofu` | version only; configuration-aware commands are excluded because parser diagnostics can echo source configuration |
| `npmReadOnly` | `npm` | dependency/environment inspection and package search paths with credential-safe aliases; unrestricted package-object `view`/`query` output is excluded |
| `pipReadOnly` | `pip` | local environment inspection: check, freeze, inspect, list, show, version |
| `uvReadOnly` | `uv` | environment/package/cache/workspace inspection paths; project `tree` is excluded because it can create or update `uv.lock` |
| `yarnReadOnly` | `yarn` | package/workspace/plugin inspection paths |

`ghApiReadOnly` still denies mutating methods, and `ghPrCreate` still blocks
non-allowlisted targets and unsafe forms. Owned API reads and allowlisted PR
creation remain prompt-gated because GitHub CLI startup can migrate
configuration, access credential storage, check for updates, and launch
telemetry before dispatch. Pager and prompt controls remain necessary but are
not sufficient startup proofs.

`kubeseal` is intentionally not profiled: its primary purpose is reading or
creating encrypted Secret data. Runtimes and package/tool runners (`bash`,
`bun`, `node`, `python`, `ruby`, `uvx`, `corepack`, `dotenv`, `pytest`, and
`playwright-cli`) remain prompt-gated because their normal operation executes
code or loads user configuration. Database export/query clients (`pg_dump`,
`psql`, and `sqlite3`) remain prompt-gated because a read-only server query can
still export credentials or application data.

## Adding a profile

Profiles must use `analyzeStrictReadOnlyCommand` or a dedicated parser when a
safe form needs flags. Dedicated parsers must handle flag order, both attached
and separate flag values, command aliases, and shell AST wrappers. Unknown
flags or subcommands must defer, never be treated as harmless.

Project-controlled plugins and configured credential-helper execution are
outside this policy's read-only classification; this policy classifies the
requested CLI operation itself.

## Policy source and session identity

The profile decision is meaningful only for the exact policy bytes loaded for a
session. The CLI reports each canonical source and SHA-256 digest with
`safety-core validate`. OpenCode and Pi retain that loaded object until their
plugin/extension is restarted. Claude stores a per-session manifest containing
the selected project root, canonical global/project configuration paths and
digests, source paths and digests, and analysis limits. A later isolated Claude
hook verifies every configured file and policy source before evaluating it;
changed, re-pointed, or missing sources hard-fail rather than falling back to a
prompt or current configuration.

This is an approval/steering invariant, not an execution sandbox. A policy
exception poisons the active adapter/session and later Bash callbacks hard-fail
until restart. See [executable identity limitations](./executable-identity-limitations.md)
for filesystem and execution limits.
