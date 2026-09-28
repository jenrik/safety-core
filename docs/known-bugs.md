# Known Bugs

## Complete environment snapshots do not normalize exported Bash functions

Production adapters construct policy events with
`completePolicyInitialEnvironment`. Unlike filtered snapshots, that path does
not translate an exported Bash function such as `BASH_FUNC_helm%%` into the
synthetic `__SAFETY_CORE_BASH_FUNCTION_helm` presence fact consumed by the DSL
`hasInheritedExecutableFunction` builtin.

Consequently, a policy that allows an unqualified `helm` invocation can allow a
same-named inherited Bash function when evaluated through a production adapter.
The policy cannot distinguish a shell builtin, a Bash function, and a PATH
executable from provenance alone: provenance describes the execution route, not
command resolution.

The core must normalize exported Bash-function names for complete snapshots as
well as filtered snapshots, without retaining function bodies, and project an
explicit execution-target kind (`builtin`, `shell-function`, `external-path`,
or `unresolved`) after Bash lookup. Add production-adapter regression coverage
for present and absent inherited functions before relying on this distinction.

## Eventless shell work can be omitted from policy coverage

The policy event stream records modeled command invocations and execution gaps,
but some reachable shell work produces neither. In particular, a standalone
output redirection such as `> output` and a call to a locally defined shell
function whose body contains only eventless builtins can be omitted from the
stream while analysis is still reported complete.

Consequently, an otherwise covered command in the same Bash source can receive
an `allow` decision even when preceding omitted work can truncate or create a
file, mutate shell state, or shadow a later command. For example, a policy that
permits `command -v helm` can allow `> output; command -v helm`; a local
`command` function can likewise prevent the lookup from being modeled as the
direct builtin invocation.

The core must represent such work as policy-visible invocations or execution
gaps, or mark the analysis incomplete until it has independent coverage. Add
source-level regressions and properties for standalone output redirects and
local-function bodies before treating a zero-event or partially eventless
analysis as automatically safe.
