# `nix-prefetch-url` policy scope

## Intent

Permit Nix 2.34.8's `nix-prefetch-url` to fetch one reviewed remote file into
the default Nix store without a harness prompt. The operator accepts the
resulting Nix-store write, including the store representation changes requested
by `--unpack` and `--executable`.

## Protected action and asset

The protected boundary is an automatic `nix-prefetch-url` authorization. The
policy protects local files from being copied into the Nix store, preserves the
default Nix configuration and store routing, and rejects shell output sinks
represented on the modeled invocation. It is not a validator of remote content,
its license, integrity, availability, or its eventual use.

## Exact in-scope commands and forms

The policy permits exactly one direct, unqualified `nix-prefetch-url`
invocation that fetches one URL and may provide one expected hash. The accepted
URL schemes are `https://`, `http://`, `ftp://`, `ftps://`, and `mirror://`,
case-insensitively. It must have a non-empty parsed host and must not contain
`@`, `?`, or `#`. These restrictions exclude URL userinfo, query parameters,
and fragments; in particular, they avoid automatically passing credentials or
signed query strings. `file:` URLs and every other scheme are excluded.

The complete grammar is:

```text
nix-prefetch-url [OPTIONS ...] REMOTE_URL [EXPECTED_HASH] [OPTIONS ...]
```

The reviewed Nix 2.34.8 options may appear before the URL, between the URL and
the optional expected hash, or after the hash:

- `--type HASH_ALGORITHM`, where `HASH_ALGORITHM` is exactly `blake3`, `md5`,
  `sha1`, `sha256`, or `sha512`;
- bare `--print-path`, `--unpack`, and `--executable`; and
- `--name NAME`.

Only the documented separate-value spelling is included for `--type` and
`--name`; attached or equals forms are not accepted. Options may be repeated if
each occurrence meets this grammar. The policy accepts a syntactically present
expected hash or name and leaves detailed Nix value validation to Nix itself.

The invocation must use the direct, unqualified executable spelling, have no
command-prefix assignments, modeled redirects, pipeline, or inherited
`nix-prefetch-url` function. `NIX_CONFIG`, `NIX_CONF_DIR`, `NIX_REMOTE`, and
`NIX_USER_CONF_FILES` must be absent or have known empty values.

Statically resolved Bash bindings are treated as their known argv values. For
example, `url=https://example.test/source.tar.gz; nix-prefetch-url "$url"` is
in scope; an unresolved URL or option value defers.

## Out of scope and threat-model exclusions

The policy defers local-file prefetches, opaque or unsupported URL schemes,
URLs without a host, and URLs containing userinfo, a query, or a fragment. It
also defers `--help`, `--version`, all unknown options, `--`, attached or
equals option values, unreviewed hash algorithms, extra positional operands,
unresolved words, path-qualified executable spellings, shell functions,
assignments, modeled redirects, pipelines, and unsafe Nix-routing
configuration.

This policy evaluates only the modeled `nix-prefetch-url` invocation. A shell
wrapper, pipeline peer, or another invocation in the same source must be
separately authorized. Deliberately substituting another executable, using a
custom transport, or manipulating shell resolution to bypass this grammar is
outside the non-adversarial threat model.

The core's current compound-context limitation is also explicitly out of scope:
an enclosing brace-group or subshell redirect, or a command-substitution
assignment, can be absent from the nested invocation event. Accordingly, the
redirect and assignment checks apply only to facts on that event; they do not
prove that the complete source lacks those enclosing effects. The limitation is
tracked in [`docs/known-bugs.md`](../../../docs/known-bugs.md).

All unrelated eventless shell work is out of scope for this policy and will be
made policy-visible by a future core fix. This includes a standalone redirection
such as `> output; nix-prefetch-url REMOTE_URL`: it independently creates or
truncates `output`, but does not alter the subsequent prefetch invocation.
Here-strings are similarly omitted from modeled redirects. A direct
`nix-prefetch-url REMOTE_URL <<<"input"` is out of scope because the reviewed
Nix command has no stdin input and the here-string does not affect its URL,
hash, configuration, store target, or fetch result.

## Assumptions and non-goals

The policy relies on Nix 2.34.8 to parse its documented options, download the
requested remote resource, verify any supplied hash, and materialize the result
in the default store. It does not prove that a URL stays remote after DNS or
mirror resolution, that transport encryption or content is trustworthy, that
the resource is non-secret, or that unpacking is harmless. Normal Nix store
and user configuration behavior is trusted only when the listed routing and
configuration environment variables are absent or empty.

The direct executable spelling is not version-pinned or path-pinned; the
operator must ensure that `nix-prefetch-url` resolves to the reviewed Nix
implementation. Core modeling limitations for exported functions and shell
constructs apply only to facts carried by the modeled invocation event. The
compound-context limitation described above is accepted for this initial policy.

## Expected outcomes

- **permit:** a complete in-scope invocation yields `allow` from this
  permission policy and may fetch the remote resource into the default Nix
  store. The overall Bash source is auto-approved only if every other modeled
  invocation is also permitted and no guard denies it.
- **defer:** every incomplete, unreviewed, malformed, unsafe-environment, or
  excluded form listed above yields `defer`, preserving the harness prompt.
- **deny:** this permission policy has no `deny` rule. A separately loaded
  guard can still deny the complete request; that dominant decision is outside
  this policy's authorization decision.
