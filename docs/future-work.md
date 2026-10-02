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
