"""Version-negotiated, length-prefixed protobuf over a Unix-domain socket."""

import argparse
import os
import signal
import socketserver
import stat
from pathlib import Path
from typing import BinaryIO

from google.protobuf.message import DecodeError

from .gen import handshake_pb2, redact_v1_pb2
from .pipeline import RedactionPipeline

MAX_REQUEST_BYTES = 1024 * 1024
MAX_HANDSHAKE_BYTES = 4096
SUPPORTED_VERSIONS = frozenset({1})
PROTOCOL_ID = "safety-core-redact"


def read_frame(stream: BinaryIO, limit: int) -> bytes | None:
    """Read a whole frame; EOF is legal only between messages."""
    header = stream.read(4)
    if not header:
        return None
    if len(header) != 4:
        raise ValueError("incomplete frame")
    length = int.from_bytes(header, "big")
    if length > limit:
        raise ValueError("frame too large")
    body = stream.read(length)
    if len(body) != length:
        raise ValueError("incomplete frame")
    return body


def write_frame(stream: BinaryIO, message: bytes) -> None:
    stream.write(len(message).to_bytes(4, "big") + message)
    stream.flush()


def negotiate(raw: bytes) -> handshake_pb2.ServerHello:
    """Keep this bootstrap independent of every versioned redaction schema."""
    hello = handshake_pb2.ClientHello()
    try:
        hello.ParseFromString(raw)
    except DecodeError:
        return handshake_pb2.ServerHello(failure=handshake_pb2.ServerHello.INVALID_HANDSHAKE)
    if hello.protocol_id != PROTOCOL_ID:
        return handshake_pb2.ServerHello(failure=handshake_pb2.ServerHello.INVALID_HANDSHAKE)
    common = SUPPORTED_VERSIONS.intersection(hello.supported_versions)
    if not common:
        return handshake_pb2.ServerHello(failure=handshake_pb2.ServerHello.NO_COMMON_VERSION)
    return handshake_pb2.ServerHello(selected_version=max(common))


def process_request(raw: bytes, pipeline: RedactionPipeline) -> redact_v1_pb2.RedactResponse:
    """Only called after v1 negotiation; no input is reflected in errors."""
    request = redact_v1_pb2.RedactRequest()
    try:
        request.ParseFromString(raw)
    except DecodeError:
        return redact_v1_pb2.RedactResponse(error=redact_v1_pb2.RedactResponse.INVALID_REQUEST)
    if not request.HasField("text"):
        return redact_v1_pb2.RedactResponse(error=redact_v1_pb2.RedactResponse.INVALID_REQUEST)
    try:
        return redact_v1_pb2.RedactResponse(text=pipeline.redact(request.text))
    except Exception:
        # Presidio errors may include the supplied text; keep them off the wire and logs.
        return redact_v1_pb2.RedactResponse(error=redact_v1_pb2.RedactResponse.PROCESSING_FAILED)


class RedactionHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5)
        try:
            try:
                raw = read_frame(self.rfile, MAX_HANDSHAKE_BYTES)
            except ValueError:
                hello = handshake_pb2.ServerHello(failure=handshake_pb2.ServerHello.INVALID_HANDSHAKE)
            else:
                if raw is None:
                    return
                hello = negotiate(raw)
            write_frame(self.wfile, hello.SerializeToString())
            if hello.selected_version == 0:
                return
            # Dispatch on the selected version, not on a per-request field.
            if hello.selected_version != 1:
                return
            while True:
                try:
                    raw = read_frame(self.rfile, MAX_REQUEST_BYTES)
                except ValueError:
                    error = redact_v1_pb2.RedactResponse(error=redact_v1_pb2.RedactResponse.INVALID_REQUEST)
                    write_frame(self.wfile, error.SerializeToString())
                    return
                if raw is None:
                    return
                response = process_request(raw, self.server.pipeline)  # type: ignore[attr-defined]
                write_frame(self.wfile, response.SerializeToString())
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
