# safety-core-redact

This local service accepts tool-output text over a Unix domain socket and sends
it through a [Presidio](https://github.com/microsoft/presidio)
AnalyzerEngine → AnonymizerEngine pipeline. A custom Titus recognizer obtains
UTF-8 byte spans from [Titus](https://github.com/praetorian-inc/titus), converts
them to Presidio character offsets, and returns them as `TITUS_SECRET` findings.
Presidio then replaces every finding with `<REDACTED>`. The recognizer uses only
Titus's `scan` operation: it never requests credential validation, so detected
values never trigger outbound API calls. The OpenCode tool-result hook uses this
service when enabled in the safety-core configuration.

From the repository root on NixOS:

```sh
nix develop .#redact
cd redact-service
uv run --python python3.12 --locked safety-core-redact-service --socket /tmp/safety-core-redact.sock --titus /path/to/titus
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
`text` (including an empty string) or a generic `error` enum.

Every message on the wire is capped at **1 MiB** (handshake frames at 4 KiB).
This is a single wire-contract limit enforced identically by both peers: the
client's `MAX_MESSAGE_BYTES` (`src/redact/opencode.ts`) and the server's
`MAX_REQUEST_BYTES` (`redact-service/src/safety_core_redact/server.py`) name the
same 1 MiB value. A frame larger than the cap is rejected outright, and clients
must treat any error, timeout, socket failure, or oversized frame as failed
redaction rather than forwarding raw text. No raw request or detection spans
are logged or returned in errors.

## OpenCode

Start the service separately, then configure the socket via the Home Manager
options `programs.safetyCorePermissions.redact.opencode.enable = true` and
`programs.safetyCorePermissions.redact.opencode.socketPath = "/run/user/.../redact.sock"`.
The existing OpenCode safety-core plugin loads these from the generated global
`safety-core/config.json`. Restart OpenCode after changing its configuration.
The tool-result hook scans text output, title, and JSON metadata. It withholds
binary attachments and replaces the entire result if the service fails. Titus
must be installed separately and is started once by the service with
`titus serve`; its rules are loaded once and reused for every socket request.
If Titus is unavailable or returns malformed spans, the Presidio pipeline fails
closed.

Because redaction is fail-closed, a title, body, or metadata payload larger
than the 1 MiB message cap also withholds the **entire** tool result — even
when it contains no secrets. Large-but-benign output (big log dumps, `webfetch`
of a large page) that exceeds the cap is replaced with the placeholder title
`Tool result withheld` and body `[Tool result withheld: redaction unavailable]`
rather than shown raw. This is intentional: oversized output is never
forwarded unredacted.

Run `uv run --python python3.12 --locked --extra test pytest` for service tests.
Regenerate protobuf messages from the repository root with
`npm run generate:redact-proto` (requires Bun, `protoc`, and installed npm dependencies).
