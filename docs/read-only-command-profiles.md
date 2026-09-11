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
standalone command. They reject shell syntax, redirects, quoting, expansions,
any flag, and secret-shaped positional paths. Options may not be auto-approved
because these tools commonly use them for credentials, output files, config
selection, execution, or local mutation.

| Nix option | Executable | Approved command paths |
| --- | --- | --- |
| `ghReadOnly` | `gh` | help/version, account and repository metadata, extension/cache/search/project/ruleset/workflow inspection; `gh api` remains subject to `ghApiReadOnly` |
| `helmReadOnly` | `helm` | help/completion, env, lint, repository/search/chart metadata, verify, version |
| `argocdReadOnly` | `argocd` | account inspection, app get/history/list/resources, appset get/list, cluster/repo list, project get/list/role get/list, version |
| `cosignReadOnly` | `cosign` | env, tree, verify variants, version |
| `craneReadOnly` | `crane` | catalog, config, digest, ls, manifest, validate, version |
| `dockerReadOnly` | `docker` | info, version, search, image/network/volume and system-df metadata paths |
| `jfrogReadOnly` | `jf`, `jfrog` | config show, options, Artifactory search, stats, version |
| `kubectlReadOnly` | `kubectl` | API discovery, auth checks, context metadata, explain, non-secret get, plugin list, version |
| `nixReadOnly` | `nix` | hash, nar ls, path/store inspection, version, why-depends |
| `nixEnvReadOnly` | `nix-env` | exact version only; legacy operation flags require a dedicated parser |
| `nixStoreReadOnly` | `nix-store` | exact version only; legacy operation flags require a dedicated parser |
| `ocReadOnly` | `oc` | OpenShift equivalents of the restricted kubectl profile plus projects/whoami |
| `podmanReadOnly` | `podman` | info/version, metadata lists, diff/history/port, system metadata |
| `podmanComposeReadOnly` | `podman-compose` | images, port, ps, version |
| `skopeoReadOnly` | `skopeo` | inspect, list-tags, manifest-digest, standalone-verify, version |
| `tofuReadOnly` | `tofu` | graph, providers/schema, validate, version |
| `npmReadOnly` | `npm` | package/environment inspection paths |
| `pipReadOnly` | `pip` | local environment inspection: check, freeze, inspect, list, show, version |
| `uvReadOnly` | `uv` | environment/package/cache/workspace inspection paths |
| `yarnReadOnly` | `yarn` | package/workspace/plugin inspection paths |

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
