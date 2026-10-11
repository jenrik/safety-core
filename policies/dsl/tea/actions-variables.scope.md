# `tea actions variables` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

This policy auto-permits only Tea's default, read-only repository Actions-variable listing. The protected asset is repository Actions-variable state: creating, setting, updating, deleting, removing, or otherwise changing a variable must not be auto-permitted by this policy. At Tea commit `bcd62a1`, the parent `actions variables` route dispatches the default list behavior; the relevant upstream sources are [`cmd/actions.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions.go), [`cmd/actions/variables.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/variables.go), and [`cmd/actions/variables/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/variables/list.go).


## Accepted grammar

The route tokens are exactly `tea {actions|action} {variables|variable|vars|var}`. The invocation has no operands and must end immediately after the second route token or an accepted option/value sequence. The complete permitted route aliases are therefore `actions variables`, `actions variable`, `actions vars`, `actions var`, `action variables`, `action variable`, `action vars`, and `action var`.

After `actions` or `action` and before the variables route token, or after the variables route token and before EOF, the policy accepts zero or more occurrences of each inherited Actions option in any order and interleaving:

- Login: `--login VALUE` or `--login=VALUE`.
- Repository: `--repo VALUE` or `--repo=VALUE`.
- Output: `--output VALUE`, `--output=VALUE`, or `-o VALUE`.

Each accepted option consumes exactly one argv word as its required value. Values are not validated and may be empty or option-looking words. Each option has unbounded cardinality: no option is required, no option is mutually exclusive with another, and repeated occurrences are accepted. Long options use only the separate-value and `=` forms listed above. `-o` uses only the listed separate-value form. `-l`, `-r`, `--remote`, and `-R` are not inherited in either parent/default position.

## Explicit outcomes

- **permit:** A trusted execution target whose complete argv matches the accepted grammar and reaches EOF. This includes the parent route with no options and every accepted option ordering, placement, and repetition described above.
- **defer:** Every invocation not covered by **permit**, including root-level options before `actions`/`action`; a missing route token; an unknown route token; any child route (`list`, `ls`, `set`, `create`, `update`, `delete`, `remove`, or `rm`); an operand; `--`; an unknown option; an accepted option at another position; an option without its value; `-l`, `-r`, `--remote`, or `-R`; an attached short value such as `-oVALUE` or `-o=VALUE`; a short-option cluster; a path-qualified command; an assignment; a redirection; an inherited executable function; or a non-external-path or non-direct `tea` target.
- **deny:** Never. This policy has no deny branch.

## Exclusions, assumptions, and non-goals

The policy relies on the pinned Tea behavior that the parent route is read-only listing. It does not validate option values, repository selection, login selection, remote selection, output format, credentials, server authorization, network destination, response content, command success, or the actual remote-side behavior. It does not permit an Actions-variable mutation merely because that mutation can be expressed through another Tea route or another client. The threat model is ordinary use of a compatible Tea CLI, not adversarial replacement of Tea or deliberate policy evasion through another API client.
