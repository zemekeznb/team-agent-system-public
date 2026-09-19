"""Conservative F2 baseline for extracting epistemic labels from bounded records."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ExtractionSource(StrEnum):
    AGENT_TEXT = "agent_text"
    TOOL_ACTION = "tool_action"
    TOOL_RESULT = "tool_result"
    VALIDATION_EVENT = "validation_event"
    AUTHORIZATION_EVENT = "authorization_event"


class EpistemicLabel(StrEnum):
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    DECISION = "decision"
    ACTION = "action"
    RESULT = "result"
    VALIDATION = "validation"
    AUTHORIZATION = "authorization"
    UNCLASSIFIED = "unclassified"


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    label: EpistemicLabel
    provenance: str
    needs_review: bool


_STRUCTURED_LABELS = {
    ExtractionSource.TOOL_ACTION: EpistemicLabel.ACTION,
    ExtractionSource.TOOL_RESULT: EpistemicLabel.RESULT,
    ExtractionSource.VALIDATION_EVENT: EpistemicLabel.VALIDATION,
    ExtractionSource.AUTHORIZATION_EVENT: EpistemicLabel.AUTHORIZATION,
}
_TEXT_PREFIXES = {
    "observation:": EpistemicLabel.OBSERVATION,
    "hypothesis:": EpistemicLabel.HYPOTHESIS,
    "decision:": EpistemicLabel.DECISION,
}


def extract_epistemic_label(source: ExtractionSource, text: str) -> ExtractionResult:
    """Classify only explicit bounded forms; uncertainty is reviewable, never guessed."""
    if not isinstance(source, ExtractionSource):
        raise TypeError("source must be ExtractionSource")
    if not isinstance(text, str) or not text.strip() or len(text) > 65_536:
        raise ValueError("text must be 1..65536 non-whitespace characters")
    if source in _STRUCTURED_LABELS:
        return ExtractionResult(_STRUCTURED_LABELS[source], "structured_event", False)

    lowered = text.strip().lower()
    matches = tuple(
        label for prefix, label in _TEXT_PREFIXES.items() if prefix in lowered
    )
    if len(matches) == 1 and lowered.startswith(
        next(prefix for prefix, label in _TEXT_PREFIXES.items() if label is matches[0])
    ):
        return ExtractionResult(matches[0], "explicit_text_prefix", False)
    return ExtractionResult(EpistemicLabel.UNCLASSIFIED, "insufficient_or_mixed", True)
