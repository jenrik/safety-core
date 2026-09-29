"""A deliberately small Presidio pipeline; recognizers can be added later."""

import spacy
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


class BlankEnglishEngine(SpacyNlpEngine):
    """Give Presidio a tokenizer without downloading a trained NLP model."""

    def __init__(self) -> None:
        super().__init__(models=[{"lang_code": "en", "model_name": "en"}])
        self.nlp = {"en": spacy.blank("en")}


class RedactionPipeline:
    def __init__(self) -> None:
        registry = RecognizerRegistry(supported_languages=["en"])
        # Seed recognizer: enough to exercise real analysis and anonymization.
        # No predefined PII recognizers or trained spaCy model are loaded.
        registry.add_recognizer(
            PatternRecognizer(
                supported_entity="GITHUB_TOKEN",
                patterns=[Pattern("classic-github-pat", r"\bghp_[A-Za-z0-9]{36}\b", 1.0)],
            )
        )
        self.analyzer = AnalyzerEngine(
            registry=registry, nlp_engine=BlankEnglishEngine(), supported_languages=["en"]
        )
        self.anonymizer = AnonymizerEngine()

    def redact(self, text: str) -> str:
        findings = self.analyzer.analyze(text=text, language="en")
        return self.anonymizer.anonymize(
            text=text,
            analyzer_results=findings,
            operators={"DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"})},
        ).text
