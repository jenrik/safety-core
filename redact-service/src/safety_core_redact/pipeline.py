"""Titus-backed secret detection and byte-accurate redaction."""

import json
import queue
import subprocess
import threading
from collections.abc import Sequence
from typing import Any

import spacy
from presidio_analyzer import (
    AnalyzerEngine,
    EntityRecognizer,
    RecognizerRegistry,
    RecognizerResult,
)
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

TITUS_RESPONSE_TIMEOUT_SECONDS = 5
TITUS_ENTITY = "TITUS_SECRET"


class TitusError(RuntimeError):
    """The local Titus scanner could not provide a trustworthy scan result."""


class TitusScanner:
    """Small client for ``titus serve``'s local NDJSON scan protocol.

    Validation is deliberately never requested: tool output must not cause the
    redactor to make network requests with a detected credential.
    """

    def __init__(self, command: Sequence[str]) -> None:
        if not command:
            raise ValueError("Titus command must not be empty")
        try:
            self.process = subprocess.Popen(
                list(command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        except OSError as error:
            raise TitusError("Titus scanner unavailable") from error
        if self.process.stdin is None or self.process.stdout is None:
            self.close()
            raise TitusError("Titus scanner unavailable")
        self.stdin = self.process.stdin
        self.stdout = self.process.stdout
        # A dedicated reader thread drains ``stdout`` line by line so callers can
        # bound their wait on a full line without relying on ``readline()``,
        # which blocks past any timeout on a partial line lacking a newline.
        self._responses: queue.Queue[str | None] = queue.Queue()
        self._reader = threading.Thread(
            target=self._read_lines, name="titus-stdout-reader", daemon=True
        )
        self._reader.start()
        try:
            ready = self._read_response()
        except TitusError:
            self.close()
            raise
        if ready.get("success") is not True or ready.get("type") != "ready":
            self.close()
            raise TitusError("Titus scanner unavailable")

    def scan(self, text: str) -> list[tuple[int, int]]:
        try:
            self.stdin.write(
                json.dumps(
                    {
                        "type": "scan",
                        "payload": {"source": "safety-core", "content": text},
                    }
                )
                + "\n"
            )
            self.stdin.flush()
            response = self._read_response()
        except (OSError, UnicodeError) as error:
            raise TitusError("Titus scan failed") from error
        if response.get("success") is not True or response.get("type") != "scan":
            raise TitusError("Titus scan failed")
        data = response.get("data")
        if not isinstance(data, dict) or not isinstance(data.get("matches"), list):
            raise TitusError("Titus scan returned invalid findings")
        return [_span(match) for match in data["matches"]]

    def _read_lines(self) -> None:
        """Drain ``stdout`` onto the response queue, signalling EOF with ``None``."""
        try:
            for line in self.stdout:
                self._responses.put(line)
        except (OSError, ValueError):
            pass
        finally:
            self._responses.put(None)

    def _read_response(self) -> dict[str, Any]:
        try:
            line = self._responses.get(timeout=TITUS_RESPONSE_TIMEOUT_SECONDS)
        except queue.Empty:
            raise TitusError("Titus scanner timed out") from None
        if line is None:
            raise TitusError("Titus scanner closed")
        try:
            response = json.loads(line)
        except json.JSONDecodeError as error:
            raise TitusError("Titus scanner returned invalid response") from error
        if not isinstance(response, dict):
            raise TitusError("Titus scanner returned invalid response")
        return response

    def close(self) -> None:
        if getattr(self, "process", None) is None or self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)


def _span(match: Any) -> tuple[int, int]:
    """Extract Titus's half-open UTF-8 byte range without accepting guesses."""
    if not isinstance(match, dict):
        raise TitusError("Titus scan returned invalid finding")
    location = match.get("Location", match.get("location"))
    if not isinstance(location, dict):
        raise TitusError("Titus scan returned invalid finding")
    offset = location.get("Offset", location.get("offset"))
    if not isinstance(offset, dict):
        raise TitusError("Titus scan returned invalid finding")
    start = offset.get("Start", offset.get("start"))
    end = offset.get("End", offset.get("end"))
    if type(start) is not int or type(end) is not int:
        raise TitusError("Titus scan returned invalid finding")
    return start, end


def byte_spans_to_character_spans(
    text: str, spans: Sequence[tuple[int, int]]
) -> list[tuple[int, int]]:
    """Convert Titus's UTF-8 offsets to the character offsets Presidio expects."""
    encoded = text.encode("utf-8")
    boundaries = {0: 0}
    byte_offset = 0
    for character_offset, character in enumerate(text, start=1):
        byte_offset += len(character.encode("utf-8"))
        boundaries[byte_offset] = character_offset
    character_spans: list[tuple[int, int]] = []
    for start, end in spans:
        if start < 0 or end <= start or end > len(encoded):
            raise TitusError("Titus scan returned invalid span")
        if start not in boundaries or end not in boundaries:
            raise TitusError("Titus scan returned invalid span")
        character_spans.append((boundaries[start], boundaries[end]))
    return character_spans


class BlankEnglishEngine(SpacyNlpEngine):
    """Give Presidio a tokenizer without downloading a trained NLP model."""

    def __init__(self) -> None:
        super().__init__(models=[{"lang_code": "en", "model_name": "en"}])
        self.nlp = {"en": spacy.blank("en")}


class TitusRecognizer(EntityRecognizer):
    """Expose Titus detections to Presidio's normal analysis pipeline."""

    def __init__(self, scanner: TitusScanner) -> None:
        self.scanner = scanner
        super().__init__(
            supported_entities=[TITUS_ENTITY],
            name="TitusRecognizer",
            supported_language="en",
        )

    def load(self) -> None:
        """The long-lived Titus subprocess is initialized by ``TitusScanner``."""

    def analyze(
        self, text: str, entities: list[str], nlp_artifacts: Any
    ) -> list[RecognizerResult]:
        if TITUS_ENTITY not in entities:
            return []
        spans = byte_spans_to_character_spans(text, self.scanner.scan(text))
        return [
            RecognizerResult(entity_type=TITUS_ENTITY, start=start, end=end, score=1.0)
            for start, end in spans
        ]


class RedactionPipeline:
    def __init__(self, titus_command: Sequence[str] = ("titus", "serve")) -> None:
        self.scanner = TitusScanner(titus_command)
        self.recognizer = TitusRecognizer(self.scanner)
        registry = RecognizerRegistry(supported_languages=["en"])
        registry.add_recognizer(self.recognizer)
        self.analyzer = AnalyzerEngine(
            registry=registry,
            nlp_engine=BlankEnglishEngine(),
            supported_languages=["en"],
        )
        self.anonymizer = AnonymizerEngine()
        # A Titus stream has ordered request/response pairs, so share it safely
        # if a threaded socket server is introduced later.
        self.lock = threading.Lock()

    def redact(self, text: str) -> str:
        with self.lock:
            findings = self.analyzer.analyze(
                text=text, language="en", entities=[TITUS_ENTITY]
            )
            return self.anonymizer.anonymize(
                text=text,
                analyzer_results=findings,
                operators={
                    "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"})
                },
            ).text

    def close(self) -> None:
        self.scanner.close()
