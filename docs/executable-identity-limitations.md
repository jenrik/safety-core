# Executable identity limitations

Executable identity helps policy authors distinguish a spelling from a resolved
program. For a known command, `safety-core` records the spelling, basename,
PATH-selected path, canonical symlink target, and ordered symlink chain. DCRM
can select exact basename, selected-path, canonical-target, or chain member.
If PATH, a filesystem lookup, a symlink, or a dynamic command is unresolved,
path-dependent identity is incomplete and must not prove a path-specific allow.

This is not a kernel execution guarantee. The following boundaries remain:

- `PATH` is analyzed as supplied shell state. A command can be shadowed by a
  shell function, alias-like wrapper route, changed PATH entry, or an executable
  replaced after analysis.
- Symlink resolution follows a bounded userspace model. It detects ordinary
  broken links, loops, and excessive depth, but a link or target may change
  between lookup and exec (TOCTOU).
- Nix store paths make deployment identity clearer and normally immutable, but
  they do not prove the active shell PATH, a wrapper's behavior, mount namespace,
  or the identity of a non-store executable.
- Home Manager profiles and XDG configuration links are activation-time
  projections. A profile switch, configuration link replacement, or garbage
  collection can re-target the installed hook/configuration path; they do not
  pin the active process to one profile generation or prevent later replacement.
- Wrapper scripts, shims, launchers, and package-manager dispatchers can load
  configuration, run hooks, choose another executable, or mutate state after
  the modeled command. Their basename or resolved target is not a proof of all
  downstream behavior.
- Hard links and bind mounts can present the same inode at multiple paths;
  pathname/symlink projections do not identify an inode, mount topology, file
  capabilities, interpreter, or dynamically loaded code.
- A policy file manifest checks canonical path and bytes when it is read. It
  cannot atomically bind a later filesystem read or `execve` to that check;
  source and executable replacement races remain possible.

For these reasons `safety-core` is not an execution broker, sandbox, mandatory
access-control system, or credential boundary. It neither intercepts every
process launch nor pins file descriptors or executable hashes through execution.
Use sandboxing, least-privilege credentials, trusted package deployment, and an
execution broker when those guarantees are required. A policy should authorize
only an operation whose modeled inputs and executable assumptions it can state
explicitly; uncertain identity should defer or deny.
