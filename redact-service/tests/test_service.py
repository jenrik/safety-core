import json
import socket
import stat
import threading

import pytest
from hypothesis import given, settings, strategies as st

from safety_core_redact.pipeline import RedactionPipeline
from safety_core_redact.server import (
    MAX_REQUEST_BYTES,
    RedactionServer,
    process_request,
)

TOKEN = "ghp_" + "A" * 36  # Generated format sentinel, never a credential.


@pytest.fixture(scope="module")
def pipeline():
    return RedactionPipeline()


def test_minimal_pipeline_redacts_seed_pattern(pipeline):
    assert pipeline.redact(f"before {TOKEN} after {TOKEN}") == "before <REDACTED> after <REDACTED>"
    assert pipeline.redact("hello world\n") == "hello world\n"
    assert len(pipeline.analyzer.registry.recognizers) == 1


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        b'{"version":2,"text":"x"}',
        b'{"version":true,"text":"x"}',
        b'{"version":1,"text":null}',
        b'{"version":1,"text":"x","extra":"x"}',
        b'{"version":1,"text":"x","text":"y"}',
        (f'{{"version":1,"text":"{TOKEN}","extra":1}}').encode(),
        b"\xff",
    ],
)
def test_invalid_requests_are_rejected_without_reflection(raw, pipeline):
    assert process_request(raw, pipeline) == {"version": 1, "error": "invalid_request"}


def test_pipeline_failure_does_not_expose_input():
    class BrokenPipeline:
        def redact(self, text):
            raise RuntimeError(text)

    response = process_request(
        json.dumps({"version": 1, "text": TOKEN}).encode(), BrokenPipeline()
    )
    assert response == {"version": 1, "error": "processing_failed"}
    assert TOKEN not in json.dumps(response)


@pytest.fixture
def live_server(tmp_path, pipeline):
    path = tmp_path / "redact.sock"
    with RedactionServer(path, pipeline) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        try:
            yield path
        finally:
            server.shutdown()
            thread.join(timeout=5)
    assert not path.exists()


def exchange(path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(path))
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        return client.makefile("rb").readline()


def test_unix_socket_roundtrip_permissions_and_multiple_connections(live_server):
    assert stat.S_IMODE(live_server.stat().st_mode) == 0o600
    for text in [f"prefix {TOKEN} suffix", "another request"]:
        response = json.loads(exchange(live_server, json.dumps({"version": 1, "text": text}).encode() + b"\n"))
        assert response == {"version": 1, "text": text.replace(TOKEN, "<REDACTED>")}
    assert json.loads(exchange(live_server, b'{"version":1,"text":"x"}')) == {
        "version": 1, "error": "invalid_request"
    }
    assert json.loads(exchange(live_server, b" " * MAX_REQUEST_BYTES + b"\n")) == {
        "version": 1, "error": "invalid_request"
    }


def test_existing_socket_path_is_not_replaced(tmp_path, pipeline):
    path = tmp_path / "redact.sock"
    path.write_text("existing file")
    with pytest.raises(OSError):
        RedactionServer(path, pipeline)
    assert path.read_text() == "existing file"


@settings(max_examples=40, deadline=None)
@given(
    prefix=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=100),
    suffix=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=100),
)
def test_arbitrary_unicode_survives_protocol_without_matching_token(pipeline, prefix, suffix):
    text = f"{prefix}\n{suffix}"
    request = json.dumps({"version": 1, "text": text}).encode("utf-8")
    assert process_request(request, pipeline) == {"version": 1, "text": text}


@settings(max_examples=40, deadline=None)
@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=36, max_size=36))
def test_token_payload_is_redacted_without_returning_its_value(pipeline, payload):
    token = "ghp_" + payload
    text = f"é\n{token} and {token}!"
    response = process_request(json.dumps({"version": 1, "text": text}).encode(), pipeline)
    assert response == {"version": 1, "text": "é\n<REDACTED> and <REDACTED>!"}
    assert token not in json.dumps(response)
