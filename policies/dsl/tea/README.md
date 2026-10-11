# Tea command policy inventory

This inventory covers every command path in Tea's upstream `main` command
registry.

**Classification scope:** Each classification applies only to the exact command
path in its row, including that command's own arguments and flags. It does not
include nested subcommands. For example, `tea pr` is strictly read-only even
though `tea pr merge` mutates a pull request.

`primarily read-only` commands normally inspect data but include an explicit
write path in their own arguments or flags; their eventual policies must
enumerate the read-only grammar rather than allow the command wholesale.

Aliases apply to the command token in that row. For example, `tea pulls
checkout` may also be invoked as `tea pr co`.

| Command | Aliases | Classification |
| --- | --- | --- |
| `tea help` | `h` | strictly read-only |
| `tea logins` | `login` | strictly read-only |
| `tea logins list` | `ls` | strictly read-only |
| `tea logins add` |  | mutating/writes |
| `tea logins edit` | `e` | mutating/writes |
| `tea logins delete` | `rm` | mutating/writes |
| `tea logins default` |  | primarily read-only |
| `tea logins helper` | `git-credential` | strictly read-only |
| `tea logins helper store` | `erase` | strictly read-only |
| `tea logins helper setup` |  | mutating/writes |
| `tea logins helper get` |  | primarily read-only |
| `tea logins oauth-refresh` |  | mutating/writes |
| `tea logins status` |  | strictly read-only |
| `tea logout` |  | mutating/writes |
| `tea whoami` |  | strictly read-only |
| `tea issues` | `issue`, `i` | strictly read-only |
| `tea issues list` | `ls` | strictly read-only |
| `tea issues create` | `c` | mutating/writes |
| `tea issues edit` | `e` | mutating/writes |
| `tea issues reopen` | `open` | mutating/writes |
| `tea issues close` |  | mutating/writes |
| `tea pulls` | `pull`, `pr` | strictly read-only |
| `tea pulls list` | `ls` | strictly read-only |
| `tea pulls checkout` | `co` | mutating/writes |
| `tea pulls clean` |  | mutating/writes |
| `tea pulls create` | `c` | mutating/writes |
| `tea pulls close` |  | mutating/writes |
| `tea pulls reopen` | `open` | mutating/writes |
| `tea pulls edit` | `e` | mutating/writes |
| `tea pulls review` |  | mutating/writes |
| `tea pulls approve` | `lgtm`, `a` | mutating/writes |
| `tea pulls reject` |  | mutating/writes |
| `tea pulls merge` | `m` | mutating/writes |
| `tea pulls reply` |  | mutating/writes |
| `tea pulls review-comments` | `rc` | strictly read-only |
| `tea pulls resolve` |  | mutating/writes |
| `tea pulls unresolve` |  | mutating/writes |
| `tea labels` | `label` | strictly read-only |
| `tea labels list` | `ls` | strictly read-only |
| `tea labels create` | `c` | mutating/writes |
| `tea labels update` |  | mutating/writes |
| `tea labels delete` | `rm` | mutating/writes |
| `tea milestones` | `milestone`, `ms` | strictly read-only |
| `tea milestones list` | `ls` | strictly read-only |
| `tea milestones create` | `c` | mutating/writes |
| `tea milestones close` |  | mutating/writes |
| `tea milestones delete` | `rm` | mutating/writes |
| `tea milestones reopen` | `open` | mutating/writes |
| `tea milestones issues` | `i` | strictly read-only |
| `tea milestones issues add` | `a` | mutating/writes |
| `tea milestones issues remove` | `r` | mutating/writes |
| `tea releases` | `release`, `r` | strictly read-only |
| `tea releases list` | `ls` | strictly read-only |
| `tea releases create` | `c` | mutating/writes |
| `tea releases delete` | `rm` | mutating/writes |
| `tea releases edit` | `e` | mutating/writes |
| `tea releases assets` | `asset`, `a` | strictly read-only |
| `tea releases assets list` | `ls` | strictly read-only |
| `tea releases assets create` | `c` | mutating/writes |
| `tea releases assets delete` | `rm` | mutating/writes |
| `tea times` | `time`, `t` | strictly read-only |
| `tea times add` | `a` | mutating/writes |
| `tea times delete` | `rm` | mutating/writes |
| `tea times reset` |  | mutating/writes |
| `tea times list` | `ls` | strictly read-only |
| `tea organizations` | `organization`, `org` | strictly read-only |
| `tea organizations list` | `ls` | strictly read-only |
| `tea organizations create` | `c` | mutating/writes |
| `tea organizations delete` | `rm` | mutating/writes |
| `tea repos` | `repo` | strictly read-only |
| `tea repos list` | `ls` | strictly read-only |
| `tea repos search` | `s` | strictly read-only |
| `tea repos create` | `c` | mutating/writes |
| `tea repos create-from-template` | `ct` | mutating/writes |
| `tea repos fork` | `f` | mutating/writes |
| `tea repos migrate` | `m` | mutating/writes |
| `tea repos delete` | `rm` | mutating/writes |
| `tea repos edit` | `e` | mutating/writes |
| `tea branches` | `branch`, `b` | strictly read-only |
| `tea branches list` | `ls` | strictly read-only |
| `tea branches protect` | `P` | mutating/writes |
| `tea branches unprotect` | `U` | mutating/writes |
| `tea branches rename` | `rn` | mutating/writes |
| `tea actions` | `action` | strictly read-only |
| `tea actions secrets` | `secret` | strictly read-only |
| `tea actions secrets list` | `ls` | strictly read-only |
| `tea actions secrets create` | `add`, `set` | mutating/writes |
| `tea actions secrets delete` | `remove`, `rm` | mutating/writes |
| `tea actions variables` | `variable`, `vars`, `var` | strictly read-only |
| `tea actions variables list` | `ls` | strictly read-only |
| `tea actions variables set` | `create`, `update` | mutating/writes |
| `tea actions variables delete` | `remove`, `rm` | mutating/writes |
| `tea actions runs` | `run` | strictly read-only |
| `tea actions runs list` | `ls` | strictly read-only |
| `tea actions runs view` | `show`, `get` | strictly read-only |
| `tea actions runs delete` | `remove`, `rm`, `cancel` | mutating/writes |
| `tea actions runs logs` | `log` | strictly read-only |
| `tea actions workflows` | `workflow` | strictly read-only |
| `tea actions workflows list` | `ls` | strictly read-only |
| `tea actions workflows view` | `show`, `get` | strictly read-only |
| `tea actions workflows dispatch` | `trigger`, `run` | mutating/writes |
| `tea actions workflows enable` |  | mutating/writes |
| `tea actions workflows disable` |  | mutating/writes |
| `tea wiki` |  | strictly read-only |
| `tea wiki list` | `ls` | strictly read-only |
| `tea wiki view` |  | strictly read-only |
| `tea wiki revisions` | `history` | strictly read-only |
| `tea wiki create` | `c` | mutating/writes |
| `tea wiki edit` | `e` | mutating/writes |
| `tea wiki delete` | `rm` | mutating/writes |
| `tea webhooks` | `webhook`, `hooks`, `hook` | strictly read-only |
| `tea webhooks list` | `ls` | strictly read-only |
| `tea webhooks create` | `c` | mutating/writes |
| `tea webhooks delete` | `rm` | mutating/writes |
| `tea webhooks update` | `edit`, `u` | mutating/writes |
| `tea comments` | `comment`, `c` | mutating/writes |
| `tea comments add` | `a` | mutating/writes |
| `tea comments list` | `ls` | strictly read-only |
| `tea comments edit` | `e` | mutating/writes |
| `tea comments delete` | `rm` | mutating/writes |
| `tea open` | `o` | primarily read-only |
| `tea notifications` | `notification`, `n` | strictly read-only |
| `tea notifications ls` | `list` | strictly read-only |
| `tea notifications read` | `r` | mutating/writes |
| `tea notifications unread` | `u` | mutating/writes |
| `tea notifications pin` | `p` | mutating/writes |
| `tea notifications unpin` |  | mutating/writes |
| `tea clone` | `C` | mutating/writes |
| `tea ssh-keys` | `ssh-key` | strictly read-only |
| `tea ssh-keys list` | `ls` | strictly read-only |
| `tea ssh-keys add` |  | mutating/writes |
| `tea ssh-keys delete` | `rm` | mutating/writes |
| `tea admin` | `a` | strictly read-only |
| `tea admin users` | `u` | strictly read-only |
| `tea admin users list` | `ls` | strictly read-only |
| `tea admin users create` | `add`, `new` | mutating/writes |
| `tea admin users edit` | `update`, `e`, `u` | mutating/writes |
| `tea admin users delete` | `rm`, `remove` | mutating/writes |
| `tea api` |  | mutating/writes |
| `tea man` |  | primarily read-only |
| `tea completion` |  | strictly read-only |
| `tea completion bash` |  | strictly read-only |
| `tea completion zsh` |  | strictly read-only |
| `tea completion fish` |  | strictly read-only |
| `tea completion pwsh` |  | strictly read-only |

`man` is hidden but can write when passed `--out`; `api` permits arbitrary HTTP
methods and can write a response to a local file. `open` has no data mutation
path but intentionally launches a browser, so it is not strictly read-only.
`completion` is provided by Tea's CLI framework rather than its explicit
command registry.

Source: <https://gitea.com/gitea/tea>
