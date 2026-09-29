# JFrog CLI administrative read-only policy plan

**Status:** discovery complete; no policy artifact has been authored.

## Goal

Plan a small family of declarative `safety-core/bash-policy-v1` permission
policies for inspection of JFrog Platform administrative state. The intended
initial focus is permission targets, repository configuration, and projects;
users, groups, workers, and service/product metadata are secondary candidates.

This is deliberately not a blanket "`jf` uses GET" policy. A command is
eligible for automatic permission only when it has a documented read-only
effect *and* its output is acceptable to disclose under the deployment's
credential and administrative-data rules. Every command, option, endpoint, or
output class not explicitly selected must defer to the harness.

No `.policy.json` or `.scope.md` is created by this planning step. When an
artifact is approved, its co-located scope document is mandatory and must be
written before the policy is finalized.

## Discovery baseline

The local Nix package was inspected as `jf version 2.124.0` with a minimal,
non-secret environment:

```sh
env -i PATH="$PATH" HOME=/tmp/jf-policy-home NIX_PATH="$NIX_PATH" \
  nix-shell -p jfrog-cli --run 'jf --version; jf api --help; jf rt --help'
```

`jf access`, `jf project`, and `jf platform` are not command namespaces in
this version. Administrative operations are split between `jf rt` and the
generic `jf api` HTTP client. The package's embedded API documentation is a
stub, so it cannot be the source of an endpoint allowlist; pin endpoint
semantics to the target Platform/Artifactory version and official REST API
documentation when authoring a policy.

The existing `jfrogReadOnly` profile covers `config show`, `options`,
Artifactory search, stats, and version. It is not an administrative inspection
profile and does not cover the work proposed here.

## CLI inventory and classification

| Surface | Discovery result | Policy classification |
| --- | --- | --- |
| `jf api PATH` | Generic Platform HTTP client. Defaults to `GET`, but accepts `--method`/`-X`, `--data`/`-d`, `--input`, repeatable `--header`/`-H`, and connection/credential flags. | **Required transport for admin reads, but unsafe as a broad allow.** A future policy must constrain request method, body/header/connection flags, and a finite endpoint grammar. |
| `jf rt permission-target-{create,update,delete}` (`ptc`, `ptu`, `ptdel`) | Remote permission-target mutations. | **Exclude.** |
| `jf rt permission-target-template` (`ptt`) | Writes a JSON template to a caller-supplied local path. | **Exclude** (local write), even though it does not change platform state. |
| `jf rt repo-{create,update,delete}` (`rc`, `ru`, `rdel`) | Remote repository configuration or repository-content mutations. | **Exclude.** |
| `jf rt repo-template` (`rpt`) | Writes a repository template to a supplied local path. | **Exclude.** |
| `jf rt replication-{create,delete,template}` (`rplc`, `rpldel`, `rplt`) | The first two mutate remote replication; the template form writes locally. | **Exclude.** |
| `jf rt` user/group commands (`gau`, `gc`, `gdel`, `user-create`, `uc`, `udel`) | Remote identity/group membership mutations. | **Exclude.** |
| `jf access-token-create` (`atc`) | Creates and returns a credential. | **Exclude.** |
| `jf rt transfer-*` | Copies/merges configuration and data, installs a plugin, or changes transfer settings. | **Exclude.** |
| `jf worker {list|ls}`, `list-event` (`le`), `execution-history` (`exec-hist`, `eh`) | Documented inspection commands. `execution-history` can read local `manifest.json` when no worker key is supplied. | **Later, separate policy candidate.** Decide whether worker execution/output metadata is safe to disclose and require an explicit worker key if local-manifest reads are not acceptable. |
| `jf rt ping` (`p`), `jf stats` (`st`) | Connectivity/product-statistics inspection. | **Low-risk, separate utility policy candidate;** not sufficient for the administrative goal. |
| `jf config show` (`s`) and `jf config export` (`ex`) | `show` exposes local server configuration; `export` produces an importable configuration token. | **Do not add to the admin policy.** Keep the existing treatment under separate credential-output review; `export` remains excluded. |
| `jf rt curl` (`cl`) | Free-form cURL invocation with arbitrary HTTP methods and cURL write/output behavior. | **Exclude.** |

The `jf` CLI therefore supplies no purpose-built read/list commands for
permission targets, repository configuration, projects, users, or groups in
this version. Those reads must be designed around a narrowly constrained
`jf api` policy rather than around the mutating `jf rt` administration verbs.

## Candidate administrative read surface

The following are candidate endpoint *families*, not authorization decisions.
Their exact GET routes, supported query parameters, response fields, minimum
Platform version, and authorization requirements must be checked against the
target deployment's official API specification before inclusion.

| Administrative asset | Candidate API family | Known route/evidence | Main disclosure question |
| --- | --- | --- | --- |
| Platform permission targets | Access v2 permissions | `GET /access/api/v2/permissions` is documented as the permission list endpoint (Artifactory 7.72.0+). A separately verified detail route is needed before permitting detail inspection. | Permission assignments expose repository names, groups, users, and access model. Confirm that this administrative data may be shown to the agent. |
| Legacy Artifactory repository permission targets | Artifactory security permissions | `GET /artifactory/api/security/permissions` and a name-specific detail endpoint are documented but deprecated in favor of Access v2. | Same disclosure concern; use only when the target still requires the legacy resource model. |
| Repository inventory | Artifactory repositories | `GET /artifactory/api/repositories` lists repository metadata and accepts type/package/project filters. | Repository names and package topology may be sensitive. |
| Repository configuration | Artifactory repository configurations | `GET /artifactory/api/repositories/configurations` is documented as listing configurations. Per-repository configuration needs separate route/version validation. | High risk: remote repository/proxy configuration can contain URLs, usernames, certificate settings, or fields whose redaction behavior differs by server version and caller privilege. Do not auto-permit until the response schema and redaction guarantees are reviewed. |
| Projects | Access projects | `GET /access/api/v1/projects` lists projects managed by the caller (Artifactory 7.117.5+). | Project identity, members, and resource bindings may be sensitive; detail reads need their own review. |
| Users/groups | Access identity APIs or deprecated Artifactory security APIs | Legacy list endpoints exist under `/artifactory/api/security/users` and `/artifactory/api/security/groups`, but JFrog documents Platform replacements. | Names, emails, group membership, and external-identity fields require an explicit disclosure decision. Do not put these in the first policy. |

Official discovery references used above:

- [Get Permissions](https://jfrog.com/help/r/jfrog-rest-apis/permissions)
- [Get Projects List](https://jfrog.com/help/r/jfrog-rest-apis/get-projects-list)
- [Get Repositories by Type and Project](https://jfrog.com/help/r/jfrog-rest-apis/get-repositories)
- [Get All Repository Configurations](https://jfrog.com/help/r/jfrog-rest-apis/get-all-repository-configurations)
- [Deprecated Artifactory user, group, and permission APIs](https://jfrog.com/help/r/jfrog-rest-apis/create-token-deprecated)

## Recommended policy sequence

1. **Define the administrative disclosure boundary.** Resolve the open
   questions below. In particular, decide whether repository configuration,
   user/group membership, and permission detail are acceptable output. This is
   an operator decision, not a property inferred from HTTP `GET`.
2. **Author one initial, endpoint-specific permission policy** (suggested name:
   `jf-admin-api-read-only.policy.json`) with its companion
   `jf-admin-api-read-only.scope.md`. Start with only the approved list routes:
   Access v2 permission list, project list, and repository inventory. Add
   repository-configuration listing only after response-redaction review.
3. **Use a closed request grammar.** Permit only a direct `jf`/`jfrog` API
   invocation; defer any unrecognized word, `--`, prefix assignment,
   redirect, inherited executable function, or incomplete/unknown input. Model
   documented flag aliases and order variants structurally rather than matching
   a command prefix.
4. **Constrain `jf api` transport semantics.** Treat default GET and explicit
   `GET` variants (`--method GET`, `--method=GET`, and applicable `-X` forms)
   as equivalent only after confirming CLI parsing. Exclude request bodies
   (`--data`, `-d`, `--input`), arbitrary headers (`--header`, `-H`), explicit
   URLs, passwords, access tokens, client/SSH key paths, and TLS bypass. Decide
   separately whether configured `--server-id`, `--timeout`, and `--verbose`
   are permissible. The default configured server is the safest initial form.
5. **Encode endpoint paths as a finite, parsed allowlist.** Do not authorize
   `jf api` merely because `GET` is the default. Avoid raw `startsWith` rules
   that could accept path-normalization or query-string variants not reviewed.
   Define which path parameters are legal, whether a request may carry query
   parameters (including pagination), and their value grammar.
6. **Add detail endpoints only per asset.** Permission detail, repository
   configuration/detail, project detail, group detail, and user detail should
   be separate scope increments, each with response-disclosure review and
   command examples.
7. **Consider separate utility policies later.** `jf rt ping`, `jf stats`, and
   workers inspection have distinct data and local-file behavior. Do not fold
   them into the administrative API scope merely for convenience.

## Required scope decisions before authoring

The operator must resolve these ambiguities before any endpoint is considered
in scope:

1. Which JFrog Platform/Artifactory versions and base deployment topology are
   supported? The current local CLI version does not establish server API
   availability or response schemas.
2. Is output of permission lists/details, project metadata, repository names,
   repository configuration, user lists, group lists, and worker execution
   history acceptable for automatic display? Which fields are considered
   credentials or sensitive operational data?
3. Is the default locally configured server the sole approved target, or may
   the policy accept `--server-id`? Are explicit `--url` and ambient/prefix
   credentials always out of scope?
4. Are pagination and read-only filtering query parameters allowed? If so,
   name the exact parameters and bounds rather than allowing arbitrary query
   strings.
5. Do routes containing a dynamic resource name belong in the first scope, or
   should the initial policy permit list routes only?
6. Should policy selectors cover both executable names `jf` and `jfrog`? The
   current legacy read-only profile does; the installed package was invoked as
   `jf`, so executable identity and aliases must be tested explicitly.
7. Should the policy evaluate only literal direct invocations, or projected
   child invocations reached through standard shell wrappers? The scope must
   state this precisely and tests must cover the selected behavior.

## Implementation and evidence checklist

For each approved future policy:

- Create the `.policy.json` and co-located `.scope.md` together. The scope must
  state intent, protected asset, exact commands/forms, exclusions/threat-model
  boundaries, assumptions/non-goals, and complete `permit`/`defer`/`deny`
  behavior.
- Build a dedicated, temporary non-secret `safety-core` configuration that
  selects the edited policy. Before and after policy/configuration changes,
  run `safety-core validate` in a minimal environment and record canonical
  source paths and SHA-256 digests.
- Run `env -i PATH="$PATH" safety-core --config /absolute/config.json explain
  --json -- '<bash-source>'` for every declared outcome. Verify modeled events
  as well as the decision, covering `jf`/`jfrog`, endpoint forms, explicit GET
  flag aliases and ordering, approved query forms, unknown paths, data/header
  flags, non-GET methods, `--`, redirects, assignments, and executable/wrapper
  behavior chosen by scope.
- Add direct and property tests for command aliases, flag placement, value
  forms, endpoint segment boundaries, and plausible fail-open gaps. Unknown
  commands, options, paths, and incomplete requests must defer.
- Before finalization, send the policy, scope document, CLI evidence, test
  evidence, and relevant implementation to the Bash policy adversarial
  reviewer. Present all findings to the operator; make no review-driven edits
  until the operator directs them, then re-review approved corrections.

## Explicit non-goals

This plan does not authorize mutation through any JFrog CLI command or raw API
method; access-token creation or export; arbitrary `jf api` requests; arbitrary
`jf rt curl`; reading template/spec/body/key files; configuration changes;
uploads/downloads; or attempting to prevent a malicious agent from using a
different executable or custom HTTP client. The policy threat model remains
natural, non-adversarial command use.
