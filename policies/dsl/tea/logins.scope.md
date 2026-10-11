# `tea logins` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected assets

This scope permits only Tea's parent login inspection behavior: listing persisted login metadata or showing the metadata for one configured login. It protects persisted Tea login configuration, including stored credentials and default-login state, from login creation, editing, deletion, default selection, credential-helper actions, and OAuth refresh. At pinned Tea `bcd62a1`, no operand calls `RunLoginList`; one operand calls `runLoginDetail`. Neither parent action makes a Gitea API request. Sources: [`cmd/login.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/login.go) and [`modules/print/login.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/modules/print/login.go).


## Accepted grammar

The route is exactly `tea {logins|login} [LOGIN]`. The top-level token must be first: root-level options are not accepted. `LOGIN` is optional, has cardinality zero or one, and must be one non-dash argv token. With no `LOGIN`, Tea lists configured logins; with one, it shows that login's details. A second bare operand defers.

The optional `LOGIN` cannot be a registered child route token or alias: `list`, `ls`, `add`, `edit`, `e`, `delete`, `rm`, `default`, `helper`, `git-credential`, `oauth-refresh`, or `status`. Those tokens are delegated to their own policies or native permission handling; a different non-dash word remains a permitted detail lookup, including a name Tea later reports as absent.

At either the parent position (after `{logins|login}` and before `LOGIN`) or the detail position (after `LOGIN`), the policy accepts each of these required-value option families zero or more times, in any order:

- `--login VALUE`, `--login=VALUE`, or `-l VALUE`
- `--repo VALUE`, `--repo=VALUE`, or `-r VALUE`
- `--remote VALUE`, `--remote=VALUE`, or `-R VALUE`
- `--output VALUE`, `--output=VALUE`, or `-o VALUE`

Each `VALUE` is exactly one argv token and is otherwise unconstrained by this policy, including an option-looking token. No option is required, mutually exclusive, or cardinality-limited; every accepted family may repeat. Long options allow only separate-value and `=` forms. Short options allow only separate values. Attached short values, `-x=VALUE`, short-option clusters, unknown options, and options outside the parent or detail position defer. The accepted option grammar is the policy's complete allowlist; Tea remains responsible for whether an accepted value or placement is meaningful.

## Threat model and non-goals

The contract covers ordinary use of a Tea-compatible external CLI, not adversarial attempts to evade policy with another executable or transport. It does not validate login names or option values, inspect or redact Tea configuration, guarantee that login metadata is non-sensitive, establish remote authorization, or authorize any nested or sibling `logins` operation.

## Outcomes

Allow only a complete accepted grammar at EOF. Any named child route, missing option value, unknown or misplaced option, malformed option form, excess or dash-prefixed operand, or route mismatch defers. This policy has no deny outcome.
