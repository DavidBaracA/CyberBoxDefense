"""Reasoning boundary for the LangGraph-backed Blue agent.

The reasoner accepts only Blue-safe observables and inferred summaries.

TODO:
- Add prompt versioning and experiment metadata for thesis evaluation runs.
- Add richer structured outputs once the Blue agent supports more attack classes.
- Consider an embedding-assisted retrieval step for historical baselines.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional, Protocol
from urllib import error, request

from ...runtime_settings import get_runtime_bool, get_runtime_float, get_runtime_setting


DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "gemma3:1b"
DEFAULT_OLLAMA_TIMEOUT_SECONDS = 120.0
DEFAULT_OLLAMA_THINK = False
DEFAULT_BLUE_MODEL_ID = "gemma3:1b"


@dataclass(frozen=True)
class BlueReasonerModelOption:
    """Selectable Blue reasoning model option for local experiment comparison."""

    model_id: str
    label: str
    ollama_model: str
    description: str


BLUE_REASONER_MODEL_OPTIONS: tuple[BlueReasonerModelOption, ...] = (
    BlueReasonerModelOption(
        model_id="gemma3:1b",
        label="Gemma 3 1B",
        ollama_model="gemma3:1b",
        description="Fast local model for lightweight Blue-side telemetry classification.",
    ),
)


@dataclass
class BlueReasonerInput:
    """Normalized Blue-safe evidence passed into the reasoning step."""

    target_name: str
    reasoning_depth: str
    anomaly_summary: str
    recent_event_messages: list[str]
    suspicion_score: float
    evidence_event_ids: list[str]
    available_vulnerabilities: list[dict[str, str]]


@dataclass
class BlueReasonerResult:
    """Reasoner output for one monitoring cycle."""

    predicted_attack_type: str
    confidence: float
    evidence: list[str]
    summary: str
    raw_response: Optional[str] = None


class BlueReasoner(Protocol):
    """Interface for Blue-side classification from allowed observables only."""

    @property
    def name(self) -> str:
        """Human-readable runtime name for operator-visible status."""

    def reason(self, payload: BlueReasonerInput) -> BlueReasonerResult:
        """Return an inferred attack classification from Blue-safe telemetry."""

    @property
    def selected_model_id(self) -> Optional[str]:
        """Stable UI-facing model identifier when applicable."""

    @property
    def selected_model_label(self) -> Optional[str]:
        """Human-readable model label when applicable."""


class HeuristicBlueReasoner:
    """Simple deterministic fallback until Ollama is available."""

    name = "heuristic"
    selected_model_id = "heuristic"
    selected_model_label = "Heuristic Fallback"

    def reason(self, payload: BlueReasonerInput) -> BlueReasonerResult:
        lower_messages = " ".join(payload.recent_event_messages).lower()
        attack_type = "anomalous_web_activity"
        confidence = min(max(payload.suspicion_score, 0.15), 0.92)
        evidence = []

        if "xss" in lower_messages or "<script" in lower_messages or "javascript:" in lower_messages or "alert(" in lower_messages:
            attack_type = "reflected_xss_probe"
            confidence = max(confidence, 0.74)
            evidence.append("Telemetry includes reflected-XSS-like markers or script-capable request patterns.")
        elif "500" in lower_messages or "sql" in lower_messages or "/search" in lower_messages:
            attack_type = "sql_injection_probe"
            confidence = max(confidence, 0.72)
            evidence.append("Repeated HTTP 500 responses or error-heavy search behavior observed.")
        elif "/login" in lower_messages or "401" in lower_messages or "403" in lower_messages:
            attack_type = "brute_force_login"
            confidence = max(confidence, 0.64)
            evidence.append("Authentication-related failures suggest login abuse or brute-force attempts.")
        elif "upload" in lower_messages or "multipart" in lower_messages:
            attack_type = "file_upload_probe"
            confidence = max(confidence, 0.62)
            evidence.append("Upload-oriented request patterns suggest file-handling probing.")
        elif "redirect" in lower_messages or "return" in lower_messages or "next=" in lower_messages:
            attack_type = "open_redirect_probe"
            confidence = max(confidence, 0.62)
            evidence.append("Redirect-like request parameters suggest navigation-flow probing.")
        elif "/api" in lower_messages or "container signal" in lower_messages:
            attack_type = "anomalous_web_activity"
            confidence = max(confidence, 0.61)
            evidence.append("API or service-layer anomalies indicate possible API misuse.")
        else:
            evidence.append("Telemetry deviates from baseline without enough evidence for a narrower label.")

        evidence.extend(payload.recent_event_messages[:3])
        return BlueReasonerResult(
            predicted_attack_type=attack_type,
            confidence=min(confidence, 0.99),
            evidence=evidence,
            summary=f"Inferred {attack_type} from indirect telemetry on {payload.target_name}.",
            raw_response=None,
        )


class OllamaBlueReasoner:
    """Local Ollama-backed reasoner for Blue-safe telemetry classification.

    The prompt explicitly avoids attacker commands and privileged ground truth.
    """

    name = "ollama"

    def __init__(
        self,
        model: str,
        model_id: Optional[str] = None,
        model_label: Optional[str] = None,
        base_url: str = DEFAULT_OLLAMA_BASE_URL,
        timeout_seconds: float = DEFAULT_OLLAMA_TIMEOUT_SECONDS,
        think: bool = DEFAULT_OLLAMA_THINK,
    ) -> None:
        self._model = model
        self._model_id = model_id or model
        self._model_label = model_label or model
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._think = think

    @property
    def selected_model_id(self) -> Optional[str]:
        return self._model_id

    @property
    def selected_model_label(self) -> Optional[str]:
        return self._model_label

    def reason(self, payload: BlueReasonerInput) -> BlueReasonerResult:
        prompt = self._build_prompt(payload)
        response_text = self._call_ollama(prompt)
        parsed = self._parse_response(response_text)
        predicted_attack_type = self._normalize_attack_type(
            str(parsed.get("predicted_attack_type", "anomalous_web_activity")),
            payload,
        )
        return BlueReasonerResult(
            predicted_attack_type=predicted_attack_type,
            confidence=min(max(float(parsed.get("confidence", payload.suspicion_score)), 0.0), 0.99),
            evidence=[str(item) for item in parsed.get("evidence", [])][:5] or payload.recent_event_messages[:3],
            summary=str(
                parsed.get(
                    "summary",
                    f"Inferred anomalous_web_activity from indirect telemetry on {payload.target_name}.",
                )
            ),
            raw_response=response_text,
        )

    def _build_prompt(self, payload: BlueReasonerInput) -> str:
        event_limit = _event_sample_limit(payload.reasoning_depth)
        event_lines = payload.recent_event_messages[:event_limit]
        if not event_lines:
            event_lines = ["No new event messages were observed in this cycle."]
        vulnerability_lines = [
            (
                f"- {item.get('scenario_id', 'unknown')}: {item.get('display_name', 'Unknown')} "
                f"({item.get('vulnerability_class', 'generic')}) - {item.get('description', '')}"
            )
            for item in payload.available_vulnerabilities
        ]
        if not vulnerability_lines:
            vulnerability_lines = ["- anomalous_web_activity: Generic anomalous web activity."]

        return (
            "You are a Blue-team cyber defense agent in a controlled local lab. "
            "Reason only from indirect observables. Never assume access to attacker commands, "
            "payloads, or hidden ground truth. "
            "Classify the most likely attack type using only the telemetry below. "
            "Use one of the available vulnerability scenario ids when the evidence supports it; "
            "otherwise use anomalous_web_activity.\n\n"
            f"Target: {payload.target_name}\n"
            f"Blue reasoning depth: {payload.reasoning_depth}\n"
            f"Blue reasoning guidance: {_blue_reasoning_depth_guidance(payload.reasoning_depth)}\n"
            "Available vulnerability scenario ids:\n"
            + "\n".join(vulnerability_lines)
            + "\n\n"
            f"Anomaly summary: {payload.anomaly_summary}\n"
            f"Suspicion score: {payload.suspicion_score:.2f}\n"
            f"Evidence event ids: {', '.join(payload.evidence_event_ids) if payload.evidence_event_ids else 'none'}\n"
            "Recent telemetry messages:\n"
            + "\n".join(f"- {line}" for line in event_lines)
            + "\n\nReturn strict JSON with keys: predicted_attack_type, confidence, summary, evidence."
        )

    def _normalize_attack_type(self, predicted: str, payload: BlueReasonerInput) -> str:
        allowed = {
            str(item.get("scenario_id", "")).strip()
            for item in payload.available_vulnerabilities
            if str(item.get("scenario_id", "")).strip()
        }
        allowed.add("anomalous_web_activity")
        cleaned = predicted.strip()
        if cleaned in allowed:
            return cleaned
        lowered = cleaned.lower()
        aliases = {
            "sql_injection": "sql_injection_probe",
            "sqli": "sql_injection_probe",
            "xss": "reflected_xss_probe",
            "reflected_xss": "reflected_xss_probe",
            "credential_attack": "brute_force_login",
            "brute_force": "brute_force_login",
            "file_upload": "file_upload_probe",
            "open_redirect": "open_redirect_probe",
        }
        mapped = aliases.get(lowered)
        if mapped in allowed:
            return mapped
        return "anomalous_web_activity"

    def _call_ollama(self, prompt: str) -> str:
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "think": self._think,
            "format": {
                "type": "object",
                "properties": {
                    "predicted_attack_type": {"type": "string"},
                    "confidence": {"type": "number"},
                    "summary": {"type": "string"},
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "predicted_attack_type",
                    "confidence",
                    "summary",
                    "evidence",
                ],
            },
            "options": {
                "temperature": 0.1,
            },
        }
        encoded = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self._base_url}/api/generate",
            data=encoded,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self._timeout_seconds) as response:
                body = response.read().decode("utf-8")
        except error.URLError as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Ollama returned non-JSON API output.") from exc

        response_text = parsed.get("response")
        if not response_text:
            raise RuntimeError("Ollama returned an empty response payload.")
        return str(response_text)

    def _parse_response(self, response_text: str) -> dict[str, object]:
        try:
            payload = json.loads(response_text)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Ollama did not return valid JSON classification output.") from exc

        if not isinstance(payload, dict):
            raise RuntimeError("Ollama classification output was not a JSON object.")
        return payload


def _blue_reasoning_depth_guidance(reasoning_depth: str) -> str:
    """Explain operator analysis-depth intent to the Blue classifier."""
    normalized_depth = reasoning_depth.lower().strip()
    if normalized_depth == "quick":
        return (
            "Make a compact classification from the strongest recent signals. "
            "Prefer lower confidence when evidence is incomplete."
        )
    if normalized_depth == "deep":
        return (
            "Correlate a wider set of recent telemetry messages before deciding. "
            "Be more cautious with confidence and mention conflicting or weak evidence."
        )
    return (
        "Use the normal monitoring depth: classify from the current anomaly summary "
        "and representative recent telemetry without assuming attacker intent."
    )


def _event_sample_limit(reasoning_depth: str) -> int:
    """Choose how much recent telemetry context Blue sends to the reasoner."""
    normalized_depth = reasoning_depth.lower().strip()
    if normalized_depth == "quick":
        return 5
    if normalized_depth == "deep":
        return 14
    return 8


class FallbackBlueReasoner:
    """Prefer a primary reasoner and fall back cleanly if it fails."""

    def __init__(self, primary: BlueReasoner, fallback: BlueReasoner) -> None:
        self._primary = primary
        self._fallback = fallback
        self.last_used_name = primary.name
        self.last_error: Optional[str] = None

    @property
    def name(self) -> str:
        return self.last_used_name

    @property
    def selected_model_id(self) -> Optional[str]:
        return getattr(self._primary, "selected_model_id", None)

    @property
    def selected_model_label(self) -> Optional[str]:
        return getattr(self._primary, "selected_model_label", None)

    def reason(self, payload: BlueReasonerInput) -> BlueReasonerResult:
        try:
            result = self._primary.reason(payload)
            self.last_used_name = self._primary.name
            self.last_error = None
            return result
        except Exception as exc:
            self.last_used_name = self._fallback.name
            self.last_error = str(exc)
            result = self._fallback.reason(payload)
            evidence = [f"Primary Ollama reasoner unavailable: {exc}"]
            evidence.extend(result.evidence)
            return BlueReasonerResult(
                predicted_attack_type=result.predicted_attack_type,
                confidence=result.confidence,
                evidence=evidence[:5],
                summary=result.summary,
                raw_response=result.raw_response,
            )


def get_blue_reasoner_model_options() -> list[BlueReasonerModelOption]:
    """Return the small allowlist of operator-selectable Blue models."""

    return list(BLUE_REASONER_MODEL_OPTIONS)


def resolve_blue_reasoner_model_option(model_id: Optional[str]) -> Optional[BlueReasonerModelOption]:
    """Resolve one configured Blue model option by stable identifier."""

    if not model_id:
        return next(
            (option for option in BLUE_REASONER_MODEL_OPTIONS if option.model_id == DEFAULT_BLUE_MODEL_ID),
            BLUE_REASONER_MODEL_OPTIONS[0],
        )
    return next((option for option in BLUE_REASONER_MODEL_OPTIONS if option.model_id == model_id), None)


def build_blue_reasoner_from_env(model_id: Optional[str] = None) -> BlueReasoner:
    """Build the preferred Blue reasoner from local environment settings.

    Environment variables:
    - `BLUE_AGENT_REASONER`: `ollama`, `heuristic`, or `auto`
    - `OLLAMA_BASE_URL`
    - `OLLAMA_MODEL`
    - `OLLAMA_TIMEOUT_SECONDS`
    - `OLLAMA_THINK`: `true` or `false`
    """

    mode = str(get_runtime_setting("BLUE_AGENT_REASONER", "auto")).strip().lower()
    heuristic = HeuristicBlueReasoner()
    if mode == "heuristic":
        return heuristic

    selected_option = resolve_blue_reasoner_model_option(model_id)
    model = (
        selected_option.ollama_model
        if selected_option
        else str(get_runtime_setting("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)).strip()
    )
    base_url = str(get_runtime_setting("OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL)).strip()
    timeout = get_runtime_float("OLLAMA_TIMEOUT_SECONDS", DEFAULT_OLLAMA_TIMEOUT_SECONDS)
    think = get_runtime_bool("OLLAMA_THINK", DEFAULT_OLLAMA_THINK)
    ollama = OllamaBlueReasoner(
        model=model,
        model_id=selected_option.model_id if selected_option else model,
        model_label=selected_option.label if selected_option else model,
        base_url=base_url,
        timeout_seconds=timeout,
        think=think,
    )

    if mode == "ollama":
        return ollama
    return FallbackBlueReasoner(primary=ollama, fallback=heuristic)
