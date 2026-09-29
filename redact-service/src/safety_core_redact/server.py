"""One newline-delimited JSON request per Unix-domain-socket connection."""

import argparse
import json
import os
import signal
import socketserver
import stat
from pathlib import Path

from .pipeline import RedactionPipeline

MAX_REQUEST_BYTES = 1024 * 1024
PROTOCOL_VERSION = 1


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def process_request(raw: bytes, pipeline: RedactionPipeline) -> dict[str, object]:
    """Validate before calling Presidio; never put raw input in error responses."""
    try:
        request = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError):
        return {"version": PROTOCOL_VERSION, "error": "invalid_request"}
    if (
        not isinstance(request, dict)
        or set(request) != {"version", "text"}
        or type(request["version"]) is not int
        or request["version"] != PROTOCOL_VERSION
        or not isinstance(request["text"], str)
    ):
        return {"version": PROTOCOL_VERSION, "error": "invalid_request"}
    try:
        return {"version": PROTOCOL_VERSION, "text": pipeline.redact(request["text"])}
    except Exception:
        # Presidio errors may include the supplied text; keep them off the wire and logs.
        return {"version": PROTOCOL_VERSION, "error": "processing_failed"}


class RedactionHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5)
        try:
            raw = self.rfile.readline(MAX_REQUEST_BYTES + 1)
            if not raw or len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
                response = {"version": PROTOCOL_VERSION, "error": "invalid_request"}
            else:
                response = process_request(raw, self.server.pipeline)  # type: ignore[attr-defined]
            self.wfile.write((json.dumps(response, ensure_ascii=True) + "\n").encode("ascii"))
        except (OSError, TimeoutError):
            # A disconnected or stalled client must not expose its request in a traceback.
            pass


class RedactionServer(socketserver.UnixStreamServer):
    def __init__(self, path: Path, pipeline: RedactionPipeline):
        self.pipeline = pipeline
        self.path = path
        self.socket_inode: int | None = None
        # Create the socket with owner-only permissions from the outset.
        old_umask = os.umask(0o177)
        try:
            super().__init__(str(path), RedactionHandler)
        finally:
            os.umask(old_umask)
        self.socket_inode = path.lstat().st_ino

    def server_close(self) -> None:
        super().server_close()
        if self.socket_inode is None:
            return
        try:
            current = self.path.lstat()
            if stat.S_ISSOCK(current.st_mode) and current.st_ino == self.socket_inode:
                self.path.unlink()
        except FileNotFoundError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Presidio tool-output redaction on a local Unix socket")
    parser.add_argument("--socket", type=Path, required=True, help="path to the Unix socket")
    args = parser.parse_args()
    if not args.socket.is_absolute():
        parser.error("--socket must be an absolute path")
    pipeline = RedactionPipeline()  # Fail startup rather than serving without Presidio.
    def stop(_signum: int, _frame: object) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    with RedactionServer(args.socket, pipeline) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
