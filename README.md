# `safety-core`

`safety-core` is an agent-steering tool that helps reduce permission prompts for the human operator.

The goal is to identify safe, read-only commands and automatically approve a Bash tool call only when enabled policies prove every reachable modeled execution safe. It also features explicit blocking to prevent access to sensitive files and data, and to steer the agent toward safer tools.

`safety-core` is not meant to be a strong security boundary. If you need security guarantees, use mechanisms such as sandboxing and least-privilege credentials.

## How is `safety-core` different?

Unlike prefix- or regex-based matching, `safety-core` parses Bash and performs a bounded, stateful symbolic analysis of the commands that may execute. It tracks shell state, known and unknown values, branches, functions, wrappers, and nested invocations without executing them. A command is automatically approved only when the enabled policies can prove every reachable modeled execution safe; uncertain or unsupported behavior is deferred or blocked.

Prefix- and regex-based solutions often become brittle when dealing with argument ordering. For example, `kubectl` accepts the `-n <namespace>` argument in multiple positions, and the selected namespace can materially affect an approval or denial decision.
