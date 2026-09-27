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
