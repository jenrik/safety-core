# safety-core-redact: first slice

This local service accepts tool-output text over a Unix domain socket and sends
it through a minimal [Presidio](https://github.com/data-privacy-stack/presidio)
AnalyzerEngine → AnonymizerEngine pipeline. Only classic `ghp_` GitHub PATs are
recognized for now; other secrets are **not** detected. A blank English spaCy
tokenizer avoids downloading a language model. The OpenCode tool-result hook
uses this service when enabled in the safety-core configuration.

From the repository root on NixOS:

```sh
nix develop .#redact
cd redact-service
uv run --python python3.12 --locked safety-core-redact-service --socket /tmp/safety-core-redact.sock
```

The socket's parent directory must already exist; use a private directory for
multi-user environments. The service does not replace an existing socket and
removes only its own socket on clean shutdown. It creates the socket with mode
`0600`.

## Wire contract

Each message is a 4-byte big-endian payload length followed by protobuf bytes.
The **first** request on each connection is always `ClientHello` from
[`proto/handshake.proto`](proto/handshake.proto), with the fixed
`safety-core-redact` protocol ID and a list of supported versions. The
`ServerHello` selects the highest mutually supported version (currently 1),
or returns `NO_COMMON_VERSION` / `INVALID_HANDSHAKE` and closes
the connection. This handshake schema and framing remain stable even when a
future version changes the redaction messages. A client must verify the selected
version before sending a versioned request.

After successful negotiation, the connection accepts multiple
`RedactRequest` / `RedactResponse` pairs from
[`proto/redact_v1.proto`](proto/redact_v1.proto). A response contains either
`text` (including an empty string) or a generic `error` enum. Request frames
are capped at 1 MiB, handshake frames at 4 KiB. Clients must treat any error,
timeout, or socket failure as failed redaction rather than forwarding raw text.
No raw request or detection spans are logged or returned in errors.

## OpenCode

Start the service separately, then configure the socket via the Home Manager
options `programs.safetyCorePermissions.redact.opencode.enable = true` and
`programs.safetyCorePermissions.redact.opencode.socketPath = "/run/user/.../redact.sock"`.
The existing OpenCode safety-core plugin loads these from the generated global
`safety-core/config.json`. Restart OpenCode after changing its configuration.
The tool-result hook scans text output, title, and JSON metadata. It withholds
binary attachments and replaces the entire result if the service fails. This
first iteration's narrow recognizer does **not** guarantee removal of other
secrets.

Run `uv run --python python3.12 --locked --extra test pytest` for service tests.
Regenerate protobuf messages from the repository root with
`npm run generate:redact-proto` (requires Bun, `protoc`, and installed npm dependencies).
