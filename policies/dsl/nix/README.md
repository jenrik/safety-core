# Nix command policy inventory

This directory will contain read-only policy artifacts for the Nix command-line
programs. The inventory is intentionally at the executable level: it records
command names, not `nix` subcommands. Each future policy will define its own
narrow read-only subcommand and flag grammar in a co-located scope document.

## Planned command executables

- `nix`
- `nix-build`
- `nix-channel`
- `nix-collect-garbage`
- `nix-copy-closure`
- `nix-daemon`
- `nix-env`
- `nix-hash`
- `nix-instantiate`
- `nix-prefetch-url`
- `nix-shell`
- `nix-store`

The inventory does not itself grant permission to run any command or any
subcommand. Commands outside this list, including NixOS management utilities
such as `nixos-rebuild`, are not planned by this inventory and remain outside
this policy set unless added explicitly.
