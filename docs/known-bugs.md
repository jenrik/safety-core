# Known Bugs

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

## Here-string redirections are not projected as redirects

The Bash analyzer can model an invocation with a here-string redirection as an
otherwise ordinary invocation with an empty `redirects` collection. For
example, a policy that rejects redirects with `hasRedirect()` can still allow
`jf rt ping <<<"payload"` when no other policy event requires a prompt.

Consequently, a policy's redirect check applies only to redirects represented
in its event. It does not prove that the Bash source contains no input
redirection or expansion routed through a here-string.

The core must model here-strings as input redirects or emit an execution gap
that prevents automatic authorization. Add parser, walker, and packaged-CLI
regression coverage before treating here-string-free source as proved by an
empty redirect collection.
