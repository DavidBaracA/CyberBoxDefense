"""Vision-assisted page understanding reasoners for bounded Red planning.

The reasoner is used only for page classification and scenario routing against
platform-managed local targets. It must not generate unrestricted exploit logic
or arbitrary target selection.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol
from urllib import error, request

from ...runtime_settings import get_runtime_bool, get_runtime_float, get_runtime_setting


DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_OLLAMA_TIMEOUT_SECONDS = 120.0
DEFAULT_OLLAMA_THINK = False
DEFAULT_VISION_MODEL = "gemma3:4b"


@dataclass(frozen=True)
class VisionPageInput:
    """Minimal safe input for a single page-understanding request."""

    target_name: str
    page_url: str
    page_title: str
    visible_text_excerpt: str
    dom_summary: dict[str, object]
    scenario_ids: list[str]
    screenshot_path: str


@dataclass(frozen=True)
class VisionPageDecision:
    """Structured page-understanding result returned by the vision reasoner."""

    page_type: str
    confidence: float
    rationale: str
    recommended_scenarios: list[dict[str, object]]
    candidate_elements: list[dict[str, object]]
    raw_response: Optional[str] = None


@dataclass(frozen=True)
class SessionConclusionInput:
    """Safe session-level facts for an operator-facing Red conclusion."""

    target_name: str
    target_url: str
    status: str
    termination_reason: str
    analyzed_pages: list[dict[str, object]]
    completed_techniques: list[str]
    vulnerabilities: list[dict[str, object]]
    screenshot_count: int


@dataclass(frozen=True)
class SessionConclusionDecision:
    """Structured session conclusion returned by the model."""

    conclusion: str
    rationale: str
    key_observations: list[str]
    raw_response: Optional[str] = None


class PageUnderstandingReasoner(Protocol):
    """Interface for optional page-understanding reasoners."""

    @property
    def name(self) -> str:
        """Operator-visible runtime name."""

    def analyze_page(self, payload: VisionPageInput) -> VisionPageDecision:
        """Return structured page-understanding output."""


class UnavailableVisionReasoner:
    """Fallback used when only DOM heuristics should drive page analysis."""

    name = "heuristic_only"

    def analyze_page(self, payload: VisionPageInput) -> VisionPageDecision:
        _ = payload
        raise RuntimeError("Vision page analysis is disabled or unavailable.")


class OllamaVisionReasoner:
    """Ollama-backed multimodal page-understanding adapter."""

    name = "ollama_vision"

    def __init__(
        self,
        *,
        model: str = DEFAULT_VISION_MODEL,
        base_url: str = DEFAULT_OLLAMA_BASE_URL,
        timeout_seconds: float = DEFAULT_OLLAMA_TIMEOUT_SECONDS,
        think: bool = DEFAULT_OLLAMA_THINK,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._think = think

    def analyze_page(self, payload: VisionPageInput) -> VisionPageDecision:
        screenshot_base64 = base64.b64encode(Path(payload.screenshot_path).read_bytes()).decode("utf-8")
        response_text = self._call_ollama(payload, screenshot_base64)
        parsed = self._parse_response(response_text)
        return VisionPageDecision(
            page_type=str(parsed.get("page_type") or "unknown"),
            confidence=max(0.0, min(1.0, float(parsed.get("confidence") or 0.0))),
            rationale=str(parsed.get("rationale") or "Used multimodal page-understanding output."),
            recommended_scenarios=list(parsed.get("recommended_scenarios") or []),
            candidate_elements=list(parsed.get("candidate_elements") or []),
            raw_response=response_text,
        )

    def _build_prompt(self, payload: VisionPageInput) -> str:
        return (
            "You are a bounded page-understanding assistant for a local cyber-range Red agent. "
            "Your job is only to classify the current page and recommend which already-allowlisted "
            "generic scenarios look applicable. Do not invent new scenarios, payloads, exploits, "
            "targets, or steps beyond safe page understanding.\n\n"
            f"Target name: {payload.target_name}\n"
            f"Page URL: {payload.page_url}\n"
            f"Page title: {payload.page_title}\n"
            f"Visible text excerpt: {payload.visible_text_excerpt}\n"
            f"DOM summary JSON: {json.dumps(payload.dom_summary, ensure_ascii=True)}\n"
            f"Allowed scenario IDs: {json.dumps(payload.scenario_ids, ensure_ascii=True)}\n\n"
            "Return strict JSON with keys:\n"
            "- page_type: short string\n"
            "- confidence: number 0..1\n"
            "- rationale: short explanation\n"
            "- candidate_elements: array of {element_kind, text, locator_hint, confidence, signals}\n"
            "- recommended_scenarios: array of {scenario_id, confidence, rationale, supporting_signals, "
            "target_page_url, pre_action_selector, target_selector, target_parameter}. "
            "Use target hints only for observed local page URLs, visible selectors, or common query parameter names. "
            "If a search input is hidden behind a visible search icon or button, set pre_action_selector to the "
            "selector for the safe click that reveals it. "
            "Never include payloads or exploit strings in target hints.\n"
        )

    def _call_ollama(self, payload: VisionPageInput, screenshot_base64: str) -> str:
        body = {
            "model": self._model,
            "prompt": self._build_prompt(payload),
            "images": [screenshot_base64],
            "stream": False,
            "think": self._think,
            "format": {
                "type": "object",
                "properties": {
                    "page_type": {"type": "string"},
                    "confidence": {"type": "number"},
                    "rationale": {"type": "string"},
                    "candidate_elements": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "element_kind": {"type": "string"},
                                "text": {"type": "string"},
                                "locator_hint": {"type": "string"},
                                "confidence": {"type": "number"},
                                "signals": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                            "required": ["element_kind", "confidence", "signals"],
                        },
                    },
                    "recommended_scenarios": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "scenario_id": {"type": "string"},
                                "confidence": {"type": "number"},
                                "rationale": {"type": "string"},
                                "supporting_signals": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "target_page_url": {"type": "string"},
                                "pre_action_selector": {"type": "string"},
                                "target_selector": {"type": "string"},
                                "target_parameter": {"type": "string"},
                            },
                            "required": ["scenario_id", "confidence", "rationale", "supporting_signals"],
                        },
                    },
                },
                "required": [
                    "page_type",
                    "confidence",
                    "rationale",
                    "candidate_elements",
                    "recommended_scenarios",
                ],
            },
            "options": {"temperature": 0.1},
        }
        encoded = json.dumps(body).encode("utf-8")
        req = request.Request(
            f"{self._base_url}/api/generate",
            data=encoded,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self._timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except error.URLError as exc:
            raise RuntimeError(f"Ollama vision request failed: {exc}") from exc
        parsed = json.loads(raw)
        response_text = parsed.get("response")
        if not response_text:
            raise RuntimeError("Ollama vision response was empty.")
        return str(response_text)

    def _parse_response(self, response_text: str) -> dict[str, object]:
        parsed = json.loads(response_text)
        if not isinstance(parsed, dict):
            raise RuntimeError("Ollama vision output was not a JSON object.")
        return parsed


class OllamaSessionConclusionReasoner:
    """Ollama-backed Red session conclusion from already-bounded evidence."""

    name = "ollama_session_conclusion"

    def __init__(
        self,
        *,
        model: str = DEFAULT_VISION_MODEL,
        base_url: str = DEFAULT_OLLAMA_BASE_URL,
        timeout_seconds: float = DEFAULT_OLLAMA_TIMEOUT_SECONDS,
        think: bool = DEFAULT_OLLAMA_THINK,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._think = think

    def summarize_session(self, payload: SessionConclusionInput) -> SessionConclusionDecision:
        response_text = self._call_ollama(payload)
        parsed = self._parse_response(response_text)
        observations = parsed.get("key_observations") or []
        return SessionConclusionDecision(
            conclusion=str(parsed.get("conclusion") or "Red session completed."),
            rationale=str(parsed.get("rationale") or ""),
            key_observations=[str(item) for item in observations if str(item).strip()],
            raw_response=response_text,
        )

    def _build_prompt(self, payload: SessionConclusionInput) -> str:
        return (
            "You are writing a concise operator-facing conclusion for a bounded local cyber-range Red agent session. "
            "Use only the provided facts from screenshot analysis, executed techniques, and recorded findings. "
            "Do not invent findings, targets, payloads, or remediation steps.\n\n"
            f"Target name: {payload.target_name}\n"
            f"Target URL: {payload.target_url}\n"
            f"Status: {payload.status}\n"
            f"Termination reason: {payload.termination_reason}\n"
            f"Screenshot count: {payload.screenshot_count}\n"
            f"Completed techniques: {json.dumps(payload.completed_techniques, ensure_ascii=True)}\n"
            f"Analyzed pages: {json.dumps(payload.analyzed_pages, ensure_ascii=True)}\n"
            f"Recorded vulnerabilities: {json.dumps(payload.vulnerabilities, ensure_ascii=True)}\n\n"
            "Return strict JSON with keys: conclusion, rationale, key_observations."
        )

    def _call_ollama(self, payload: SessionConclusionInput) -> str:
        body = {
            "model": self._model,
            "prompt": self._build_prompt(payload),
            "stream": False,
            "think": self._think,
            "format": {
                "type": "object",
                "properties": {
                    "conclusion": {"type": "string"},
                    "rationale": {"type": "string"},
                    "key_observations": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": ["conclusion", "rationale", "key_observations"],
            },
            "options": {"temperature": 0.1},
        }
        encoded = json.dumps(body).encode("utf-8")
        req = request.Request(
            f"{self._base_url}/api/generate",
            data=encoded,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self._timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except error.URLError as exc:
            raise RuntimeError(f"Ollama session conclusion request failed: {exc}") from exc
        parsed = json.loads(raw)
        response_text = parsed.get("response")
        if not response_text:
            raise RuntimeError("Ollama session conclusion response was empty.")
        return str(response_text)

    def _parse_response(self, response_text: str) -> dict[str, object]:
        parsed = json.loads(response_text)
        if not isinstance(parsed, dict):
            raise RuntimeError("Ollama session conclusion output was not a JSON object.")
        return parsed


def build_page_understanding_reasoner() -> PageUnderstandingReasoner:
    mode = str(get_runtime_setting("RED_AGENT_VISION_REASONER", "auto")).strip().lower()
    if mode in {"disabled", "off", "heuristic"}:
        return UnavailableVisionReasoner()

    base_url = str(get_runtime_setting("OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL)).strip()
    timeout = get_runtime_float("OLLAMA_TIMEOUT_SECONDS", DEFAULT_OLLAMA_TIMEOUT_SECONDS)
    think = get_runtime_bool("OLLAMA_THINK", DEFAULT_OLLAMA_THINK)
    model = str(get_runtime_setting("RED_AGENT_VISION_MODEL", DEFAULT_VISION_MODEL)).strip()
    return OllamaVisionReasoner(
        model=model,
        base_url=base_url,
        timeout_seconds=timeout,
        think=think,
    )


def build_session_conclusion_reasoner() -> OllamaSessionConclusionReasoner:
    base_url = str(get_runtime_setting("OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL)).strip()
    timeout = get_runtime_float("OLLAMA_TIMEOUT_SECONDS", DEFAULT_OLLAMA_TIMEOUT_SECONDS)
    think = get_runtime_bool("OLLAMA_THINK", DEFAULT_OLLAMA_THINK)
    model = str(get_runtime_setting("RED_AGENT_VISION_MODEL", DEFAULT_VISION_MODEL)).strip()
    return OllamaSessionConclusionReasoner(
        model=model,
        base_url=base_url,
        timeout_seconds=timeout,
        think=think,
    )
