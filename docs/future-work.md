# Future work

## Project-policy ancestor discovery

Project-policy discovery currently selects the nearest `.safety-core/config.json`
and checks only that root against a global allowlist. A nearer nested project
configuration therefore shadows an allowlisted ancestor and fails closed to the
global policies alone. Review the desired ancestor-policy activation semantics
before changing this: in particular, decide whether an allowlisted ancestor
should remain active when a closer project configuration exists. Global policy
sources must continue to compose with, rather than be replaced by, project
policy sources.

## Declarative policy testing framework

Provide a reusable, checked-in direct and property-testing framework for
project-local DSL policies. It should exercise each documented `permit`,
`defer`, and `deny` outcome, plus declared equivalent command forms such as
flag orderings, aliases, and shell structure, and make this evidence available
to CI. The Rook Ceph toolbox policy currently has CLI evidence but no durable
policy-specific test suite.

## Bash `test` and `[` command-execution model

The initial `bash-test` policy expresses the intended permission for statically
resolved direct `test` and `[` predicate invocations. The walker currently
models `test`, but the bracket spelling is an unsupported statement and cannot
reach its policy. Determine whether the Bash walker must model both spellings
as explicit command executions for policy evaluation. The resolver recognizes
both names as Bash builtins, while the builtin state-transition handler has no
command-specific transition for either. Establish the desired event/dispatch
behavior with Bash oracle tests covering direct builtin lookup, function
shadowing, the required closing `]` for `[`, ordinary predicates, and metadata
predicates such as `-e`/`-r`.

If explicit execution modeling is required, implement it structurally rather
than special-casing individual test expressions. Preserve argv, redirection,
execution-target, and source-span evidence so a policy can distinguish `test`
from `[` and can validate the complete expression grammar. Decide and document
how filesystem-metadata predicates interact with harness file permissions;
they must not silently become an unmodeled file-read authorization. Add direct
and property tests before relying on either spelling for automatic permission.
