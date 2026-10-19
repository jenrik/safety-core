import io
import json
import shutil
import socket
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from safety_core_redact.gen import handshake_pb2, redact_v1_pb2
from safety_core_redact.pipeline import (
    TITUS_ENTITY,
    RedactionPipeline,
    TitusError,
    byte_spans_to_character_spans,
)
from safety_core_redact.server import (
    MAX_REQUEST_BYTES,
    RedactionServer,
    negotiate,
    process_request,
    read_frame,
    write_frame,
)

TOKEN = "ghp_" + "A" * 36  # Generated format sentinel, never a credential.


@pytest.fixture(scope="module")
def pipeline(tmp_path_factory):
    """A Titus serve-compatible scanner with deterministic byte spans."""
    scanner = tmp_path_factory.mktemp("titus") / "serve.py"
    scanner.write_text(
        """import json
import re
import sys

print(json.dumps({"success": True, "type": "ready", "data": {"version": "1.0.0"}}), flush=True)
for line in sys.stdin:
    request = json.loads(line)
    text = request["payload"]["content"]
    matches = []
    for found in re.finditer(r"ghp_[A-Za-z0-9]{36}", text):
        start = len(text[:found.start()].encode())
        end = len(text[:found.end()].encode())
        matches.append({"Location": {"Offset": {"Start": start, "End": end}}})
    print(json.dumps({"success": True, "type": "scan", "data": {"matches": matches}}), flush=True)
"""
    )
    instance = RedactionPipeline((sys.executable, str(scanner)))
    yield instance
    instance.close()


def frame(message):
    output = io.BytesIO()
    write_frame(output, message.SerializeToString())
    return output.getvalue()


def receive(stream, cls):
    payload = read_frame(stream, MAX_REQUEST_BYTES)
    assert payload is not None
    return cls.FromString(payload)


def test_titus_pipeline_redacts_detected_spans(pipeline):
    assert (
        pipeline.redact(f"before {TOKEN} after {TOKEN}")
        == "before <REDACTED> after <REDACTED>"
    )
    assert pipeline.redact("hello world\n") == "hello world\n"


def test_titus_utf8_spans_become_presidio_character_offsets(pipeline):
    assert byte_spans_to_character_spans("é abcd", [(3, 5), (4, 7)]) == [(2, 4), (3, 6)]
    findings = pipeline.analyzer.analyze(
        text=f"é {TOKEN}", language="en", entities=[TITUS_ENTITY]
    )
    assert [
        (finding.entity_type, finding.start, finding.end) for finding in findings
    ] == [(TITUS_ENTITY, 2, 42)]
    for spans in [[(-1, 1)], [(0, 0)], [(0, 99)], [(1, 3)]]:
        with pytest.raises(TitusError):
            byte_spans_to_character_spans("é", spans)


def test_negotiation_selects_highest_shared_version_and_rejects_other_versions():
    supported = negotiate(
        handshake_pb2.ClientHello(
            protocol_id="safety-core-redact", supported_versions=[999, 1, 0]
        ).SerializeToString()
    )
    assert supported.selected_version == 1
    assert supported.failure == handshake_pb2.ServerHello.FAILURE_UNSPECIFIED
    unsupported = negotiate(
        handshake_pb2.ClientHello(
            protocol_id="safety-core-redact", supported_versions=[999, 2]
        ).SerializeToString()
    )
    assert unsupported.selected_version == 0
    assert unsupported.failure == handshake_pb2.ServerHello.NO_COMMON_VERSION
    assert negotiate(b"\xff").failure == handshake_pb2.ServerHello.INVALID_HANDSHAKE
    assert negotiate(b"").failure == handshake_pb2.ServerHello.INVALID_HANDSHAKE
    assert (
        negotiate(
            handshake_pb2.ClientHello(
                protocol_id="other", supported_versions=[1]
            ).SerializeToString()
        ).failure
        == handshake_pb2.ServerHello.INVALID_HANDSHAKE
    )


@given(
    st.lists(st.integers(min_value=2, max_value=2**32 - 1), max_size=20), st.booleans()
)
def test_property_negotiation_is_independent_of_version_order(versions, include_v1):
    offered = [*versions, *([1] if include_v1 else [])]
    for ordering in [offered, list(reversed(offered))]:
        response = negotiate(
            handshake_pb2.ClientHello(
                protocol_id="safety-core-redact", supported_versions=ordering
            ).SerializeToString()
        )
        assert response.selected_version == (1 if include_v1 else 0)
        assert response.failure == (
            handshake_pb2.ServerHello.FAILURE_UNSPECIFIED
            if include_v1
            else handshake_pb2.ServerHello.NO_COMMON_VERSION
        )


def test_request_validation_and_generic_processing_error(pipeline):
    invalid = redact_v1_pb2.RedactResponse.INVALID_REQUEST
    assert process_request(b"\xff", pipeline).error == invalid
    assert (
        process_request(
            redact_v1_pb2.RedactRequest().SerializeToString(), pipeline
        ).error
        == invalid
    )
    assert (
        process_request(
            redact_v1_pb2.RedactRequest(text="").SerializeToString(), pipeline
        ).WhichOneof("result")
        == "text"
    )

    class BrokenPipeline:
        def redact(self, text):
            raise RuntimeError(text)

    response = process_request(
        redact_v1_pb2.RedactRequest(text=TOKEN).SerializeToString(), BrokenPipeline()
    )
    assert response.error == redact_v1_pb2.RedactResponse.PROCESSING_FAILED
    assert TOKEN.encode() not in response.SerializeToString()


@pytest.fixture
def live_server(tmp_path, pipeline):
    path = tmp_path / "redact.sock"
    with RedactionServer(path, pipeline) as server:
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}
        )
        thread.start()
        try:
            yield path
        finally:
            server.shutdown()
            thread.join(timeout=5)
    assert not path.exists()


def connect(path):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    client.connect(str(path))
    return client


def test_unix_socket_negotiates_once_then_handles_multiple_requests(live_server):
    assert stat.S_IMODE(live_server.stat().st_mode) == 0o600
    with connect(live_server) as client:
        stream = client.makefile("rb")
        client.sendall(
            frame(
                handshake_pb2.ClientHello(
                    protocol_id="safety-core-redact", supported_versions=[2, 1]
                )
            )
        )
        assert receive(stream, handshake_pb2.ServerHello).selected_version == 1
        for text in [f"prefix {TOKEN} suffix", "another request", ""]:
            client.sendall(frame(redact_v1_pb2.RedactRequest(text=text)))
            response = receive(stream, redact_v1_pb2.RedactResponse)
            assert response.WhichOneof("result") == "text"
            assert response.text == text.replace(TOKEN, "<REDACTED>")
        client.sendall(frame(redact_v1_pb2.RedactRequest()))
        assert (
            receive(stream, redact_v1_pb2.RedactResponse).error
            == redact_v1_pb2.RedactResponse.INVALID_REQUEST
        )


def test_no_shared_version_closes_before_processing_versioned_request(live_server):
    with connect(live_server) as client:
        stream = client.makefile("rb")
        client.sendall(
            frame(
                handshake_pb2.ClientHello(
                    protocol_id="safety-core-redact", supported_versions=[2]
                )
            )
            + frame(redact_v1_pb2.RedactRequest(text=TOKEN))
        )
        assert (
            receive(stream, handshake_pb2.ServerHello).failure
            == handshake_pb2.ServerHello.NO_COMMON_VERSION
        )
        assert read_frame(stream, MAX_REQUEST_BYTES) is None


def test_versioned_request_cannot_be_used_as_first_message(live_server):
    with connect(live_server) as client:
        stream = client.makefile("rb")
        client.sendall(frame(redact_v1_pb2.RedactRequest(text=TOKEN)))
        assert (
            receive(stream, handshake_pb2.ServerHello).failure
            == handshake_pb2.ServerHello.INVALID_HANDSHAKE
        )
        assert read_frame(stream, MAX_REQUEST_BYTES) is None


def test_malformed_and_oversized_frames_are_generic(live_server):
    with connect(live_server) as client:
        stream = client.makefile("rb")
        client.sendall((4097).to_bytes(4, "big"))
        assert (
            receive(stream, handshake_pb2.ServerHello).failure
            == handshake_pb2.ServerHello.INVALID_HANDSHAKE
        )
    with connect(live_server) as client:
        stream = client.makefile("rb")
        client.sendall(
            frame(
                handshake_pb2.ClientHello(
                    protocol_id="safety-core-redact", supported_versions=[1]
                )
            )
        )
        assert receive(stream, handshake_pb2.ServerHello).selected_version == 1
        client.sendall((MAX_REQUEST_BYTES + 1).to_bytes(4, "big"))
        assert (
            receive(stream, redact_v1_pb2.RedactResponse).error
            == redact_v1_pb2.RedactResponse.INVALID_REQUEST
        )


def test_existing_socket_path_is_not_replaced(tmp_path, pipeline):
    path = tmp_path / "redact.sock"
    path.write_text("existing file")
    with pytest.raises(OSError):
        RedactionServer(path, pipeline)
    assert path.read_text() == "existing file"


def test_generated_typescript_client_interoperates_with_python_service(live_server):
    root = Path(__file__).resolve().parents[2]
    if (
        shutil.which("bun") is None
        or not (root / "node_modules" / "@bufbuild" / "protobuf").exists()
        or not (root / "packages" / "core" / "dist" / "index.js").exists()
    ):
        pytest.skip("Bun and built root npm packages required for cross-language test")
    script = (
        'import { createOpenCodePlugin } from "./adapters/opencode.ts"; '
        f"const socketPath = {json.dumps(str(live_server))}; "
        "const limits = {maxFunctionDepth:8,maxNestedScriptDepth:8,maxSteps:100,maxWorkItems:100}; "
        "const runtime = {config:{bashAnalysis:limits,redact:{opencode:{enabled:true,socketPath}}},"
        "policySet:{policies:[],sources:[]},limits}; "
        "const plugin = await createOpenCodePlugin({runtime}); "
        f'const output = {{title:"read result",output:{json.dumps("before " + TOKEN + " after")},metadata:{{value:"safe"}}}}; '
        'await plugin["tool.execute.after"]({tool:"read",args:{}},output); '
        "console.log(JSON.stringify(output));"
    )
    result = subprocess.run(
        ["bun", "-e", script],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "title": "read result",
        "output": "before <REDACTED> after",
        "metadata": {"value": "safe"},
    }


@settings(max_examples=40, deadline=None)
@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=150))
def test_property_unicode_preserved_after_binary_roundtrip(pipeline, text):
    raw = redact_v1_pb2.RedactRequest(text=text).SerializeToString()
    response = process_request(raw, pipeline)
    assert (
        redact_v1_pb2.RedactResponse.FromString(response.SerializeToString()).text
        == text
    )


@settings(max_examples=40, deadline=None)
@given(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=36, max_size=36)
)
def test_property_token_payload_is_redacted_without_returning_its_value(
    pipeline, payload
):
    token = "ghp_" + payload
    response = process_request(
        redact_v1_pb2.RedactRequest(
            text=f"é\n{token} and {token}!"
        ).SerializeToString(),
        pipeline,
    )
    assert response.text == "é\n<REDACTED> and <REDACTED>!"
    assert token.encode() not in response.SerializeToString()


@settings(max_examples=80, deadline=None)
@given(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyzé\n ", max_size=80),
    st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=80),
            st.integers(min_value=0, max_value=80),
        ),
        max_size=20,
    ),
)
def test_property_titus_byte_spans_round_trip_through_presidio_offsets(
    text, candidates
):
    encoded = text.encode()
    boundaries = {0, len(encoded)}
    boundaries.update(len(text[:index].encode()) for index in range(len(text) + 1))
    spans = [(min(start, end), max(start, end)) for start, end in candidates]
    spans = [
        (start, end)
        for start, end in spans
        if start in boundaries and end in boundaries and start < end <= len(encoded)
    ]
    character_spans = byte_spans_to_character_spans(text, spans)
    assert [
        (len(text[:start].encode()), len(text[:end].encode()))
        for start, end in character_spans
    ] == spans
