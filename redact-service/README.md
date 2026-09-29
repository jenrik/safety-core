# safety-core-redact: first slice

This local service accepts tool-output text over a Unix domain socket and sends
it through a minimal [Presidio](https://github.com/data-privacy-stack/presidio)
AnalyzerEngine → AnonymizerEngine pipeline. Only classic `ghp_` GitHub PATs are
recognized for now; other secrets are **not** detected. A blank English spaCy
tokenizer avoids downloading a language model. Harness integration follows in a
later iteration.

From the repository root on NixOS:

```sh
nix develop .#redact
cd redact-service
uv run --python python3.12 --locked safety-core-redact-service --socket /tmp/safety-core-redact.sock
```

The socket's parent directory must already exist; use a private directory for
multi-user environments. The service does not replace an existing socket and
removes only its own socket on clean shutdown. It creates the socket with mode
`0600`. Request and response are one UTF-8 JSON line per connection:

```json
{"version":1,"text":"tool output"}
{"version":1,"text":"tool output"}
```

The response is either `{ "version": 1, "text": "..." }` or
`{ "version": 1, "error": "invalid_request" | "processing_failed" }`.
Requests are capped at 1 MiB (including the newline); clients must treat any
error, timeout, or socket failure as a failed redaction rather than forwarding
the original text. No raw request or detection spans are logged or returned in
errors. Run `uv run --python python3.12 --locked --extra test pytest` for tests.
