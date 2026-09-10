safety-core implement a common permission management and steering of agents.

It uses the harness' native permission system where possible, and falls back on hooks for more advanced inspection and steering.

It's implemented using a combination of harness configuration via a nix home-manager module, and a reusable typescript core for implementing hooks and harness plugins.

All configurability should be exposed as nix options that sets values in the safety-core config file.

When implementing a new set of restrictions make sure we have the strongest matching and where possible we should steer the agent toward safer alternatives or provide reasoning for why the actions is blocked. Matching should be insensitive to argument ordering and should also match alternative command that does functionally the same so the agent can't workaround the restriction by rewording the command or switching to straight API calls. At the same time don't be overly pessimistic with matching, we want to enforce specific behavior but don't want to unnecessarily inhibit an agent.

All changes must be accompanied by a set of unit tests and property tests, and before finalizing it must pass an adversarial review by a frontier model. The threat model does not include adversarial/malicious agents, only agents that uses the tool naturally, so actively trying to bypass something like `gh api` being forbidden with `curl` is out-of-scope, but making sure we have all the command aliases and argument orderings is covered.
