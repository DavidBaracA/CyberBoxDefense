"""Model-backed bounded Red planning reasoners.

These reasoners do not execute attacks. They only help choose an ordering over
the already allowlisted local scenarios so Red can be meaningfully model-backed
while staying constrained to platform-managed targets.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Optional, Protocol
from urllib import error, request

from ...red_agent_models import AttackScenario, RedAgentPageAnalysis
from ...run_models import RunConfig
from ...runtime_settings import get_runtime_bool, get_runtime_float, get_runtime_setting


DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_OLLAMA_TIMEOUT_SECONDS = 120.0
DEFAULT_OLLAMA_THINK = False
DEFAULT_OLLAMA_NUM_PREDICT = 128
DEFAULT_RED_MODEL_ID = "gemma3:27b-cloud"


@dataclass(frozen=True)
class RedPlanningModelOption:
    """Selectable Red planning model option."""

    model_id: str
    label: str
    ollama_model: str
    description: str


RED_PLANNING_MODEL_OPTIONS: tuple[RedPlanningModelOption, ...] = (
    RedPlanningModelOption(
        model_id="gemma3:27b-cloud",
        label="Gemma 3 27B Cloud",
        ollama_model="gemma3:27b-cloud",
        description="Ollama Cloud planner for bounded Red scenario ordering.",
    ),
    RedPlanningModelOption(
        model_id="gemma3:4b",
        label="Gemma 3 4B",
        ollama_model="gemma3:4b",
        description="Compact local planner for bounded Red scenario ordering.",
    ),
)


@dataclass(frozen=True)
class RedPlanningInput:
    """Safe bounded planning input for choosing scenario order."""

    target_name: str
    target_url: str
    attack_depth: str
    duration_seconds: int
    try_all_available: bool
    stop_on_first_confirmed_vulnerability: bool
    candidate_scenarios: list[AttackScenario]
    analyzed_pages: list[RedAgentPageAnalysis]


@dataclass(frozen=True)
class RedPlanningDecision:
    """Reasoner output for ordered bounded scenario execution."""

    ordered_scenario_ids: list[str]
    rationale: str
    raw_response: Optional[str] = None
    error: Optional[str] = None


def _load_json_object_from_model_response(response_text: str, *, context: str) -> dict[str, object]:
    """Parse model JSON, accepting common Markdown-wrapped cloud responses."""
    text = response_text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].lstrip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    if not text.startswith("{"):
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start : end + 1]
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        snippet = response_text[:300].replace("\n", "\\n")
        raise RuntimeError(
            f"{context} output was not valid JSON: {exc}. Response starts with: {snippet}"
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"{context} output was not a JSON object.")
    return payload


class RedPlanningReasoner(Protocol):
    """Interface for model-backed bounded Red planning."""

    @property
    def name(self) -> str:
        """Runtime name for operator-visible logs."""
        ...

    @property
    def selected_model_id(self) -> Optional[str]:
        """Stable UI-facing model identifier."""
        ...

    @property
    def selected_model_label(self) -> Optional[str]:
        """Human-readable planning model label."""
        ...

    def choose_order(self, payload: RedPlanningInput) -> RedPlanningDecision:
        """Return an ordered subset/permutation of already-allowed scenarios."""
        ...


class HeuristicRedPlanningReasoner:
    """Deterministic fallback that preserves the existing bounded planner order."""

    name = "heuristic"
    selected_model_id = "heuristic"
    selected_model_label = "Heuristic Planner"

    def choose_order(self, payload: RedPlanningInput) -> RedPlanningDecision:
        return RedPlanningDecision(
            ordered_scenario_ids=[scenario.scenario_id for scenario in payload.candidate_scenarios],
            rationale="Used deterministic bounded planner ordering.",
            raw_response=None,
            error=None,
        )


class OllamaRedPlanningReasoner:
    """Ollama-backed bounded planning reasoner for Red scenario ordering."""

    name = "ollama"

    def __init__(
        self,
        *,
        model: str,
        model_id: str,
        model_label: str,
        base_url: str = DEFAULT_OLLAMA_BASE_URL,
        timeout_seconds: float = DEFAULT_OLLAMA_TIMEOUT_SECONDS,
        think: bool = DEFAULT_OLLAMA_THINK,
    ) -> None:
        self._model = model
        self._model_id = model_id
        self._model_label = model_label
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._think = think

    @property
    def selected_model_id(self) -> Optional[str]:
        return self._model_id

    @property
    def selected_model_label(self) -> Optional[str]:
        return self._model_label

    def choose_order(self, payload: RedPlanningInput) -> RedPlanningDecision:
        prompt = self._build_prompt(payload)
        print("[RedPlanningReasoner] Prompt sent to Ollama:")
        print(prompt)
        response_text = self._call_ollama(prompt)
        print("[RedPlanningReasoner] Raw response received from Ollama:")
        print(response_text)
        parsed = self._parse_response(response_text)
        ordered_scenario_ids = parsed.get("ordered_scenario_ids", [])
        if not isinstance(ordered_scenario_ids, list):
            raise RuntimeError("Ollama planning output ordered_scenario_ids was not a list.")
        requested_ids = [str(item).strip() for item in ordered_scenario_ids]
        allowed_ids = [scenario.scenario_id for scenario in payload.candidate_scenarios]
        ordered_ids = [scenario_id for scenario_id in requested_ids if scenario_id in allowed_ids]
        for scenario_id in allowed_ids:
            if scenario_id not in ordered_ids:
                ordered_ids.append(scenario_id)
        return RedPlanningDecision(
            ordered_scenario_ids=ordered_ids,
            rationale=str(parsed.get("rationale", "Used Ollama-backed bounded scenario ordering.")),
            raw_response=response_text,
            error=None,
        )

    def _build_prompt(self, payload: RedPlanningInput) -> str:
        scenario_lines = [
            f"- {scenario.scenario_id}: {scenario.display_name}"
            for scenario in payload.candidate_scenarios
        ]
        analyzed_pages_summary = [
            {
                "page_url": page.page_url,
                "page_type": page.page_type,
                "confidence": page.confidence,
                "recommended_scenario_ids": [item.scenario_id for item in page.recommended_scenarios],
            }
            for page in payload.analyzed_pages
        ]
        depth_guidance = _attack_depth_guidance(payload.attack_depth)
        return (
            "Reorder only the allowed local Red scenarios. "
            "Do not invent scenarios, commands, payloads, or targets. "
            "Return strict JSON only: ordered_scenario_ids, rationale.\n\n"
            f"Target name: {payload.target_name}\n"
            f"Target url: {payload.target_url}\n"
            f"Attack depth: {payload.attack_depth}\n"
            f"Attack depth guidance: {depth_guidance}\n"
            f"Session duration: {payload.duration_seconds} seconds\n"
            f"Try all available scenarios: {payload.try_all_available}\n"
            "Planning rule: choose the safest useful order from the allowed list only. "
            "Prefer scenarios supported by analyzed page signals, and adapt the order to "
            "the selected attack depth and time budget.\n"
            f"Analyzed pages: {json.dumps(analyzed_pages_summary, ensure_ascii=True)}\n"
            "Allowed scenarios:\n"
            + "\n".join(scenario_lines)
        )

    def _call_ollama(self, prompt: str) -> str:
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "think": self._think,
            "format": {
                "type": "object",
                "properties": {
                    "ordered_scenario_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "rationale": {"type": "string"},
                },
                "required": ["ordered_scenario_ids", "rationale"],
            },
            "options": {
                "temperature": 0.1,
                "num_predict": DEFAULT_OLLAMA_NUM_PREDICT,
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
        except (TimeoutError, socket.timeout) as exc:
            raise RuntimeError(
                f"Ollama request timed out after {int(self._timeout_seconds)} seconds"
            ) from exc
        except error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise RuntimeError(
                    f"Ollama request timed out after {int(self._timeout_seconds)} seconds"
                ) from exc
            raise RuntimeError(f"Ollama request failed: {exc}") from exc

        parsed = json.loads(body)
        response_text = parsed.get("response")
        if not response_text:
            raise RuntimeError("Ollama returned an empty response payload.")
        return str(response_text)

    def _parse_response(self, response_text: str) -> dict[str, object]:
        return _load_json_object_from_model_response(response_text, context="Ollama planning")


def _attack_depth_guidance(attack_depth: str) -> str:
    """Explain operator depth intent to the bounded planning model."""
    normalized_depth = attack_depth.lower().strip()
    if normalized_depth == "deep":
        return (
            "Prefer thorough coverage. Include relevant multi-step and lower-confidence "
            "scenarios after high-signal checks, while still staying inside the allowed list."
        )
    return (
        "Use the normal bounded plan. Prioritize likely high-confidence matches first, "
        "then include moderate exploration if time allows."
    )


class FallbackRedPlanningReasoner:
    """Prefer a primary model-backed planner and fall back cleanly if it fails."""

    def __init__(self, primary: RedPlanningReasoner, fallback: RedPlanningReasoner) -> None:
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

    def choose_order(self, payload: RedPlanningInput) -> RedPlanningDecision:
        try:
            result = self._primary.choose_order(payload)
            self.last_used_name = self._primary.name
            self.last_error = None
            return result
        except Exception as exc:
            self.last_used_name = self._fallback.name
            self.last_error = str(exc)
            result = self._fallback.choose_order(payload)
            return RedPlanningDecision(
                ordered_scenario_ids=result.ordered_scenario_ids,
                rationale=result.rationale,
                raw_response=result.raw_response,
                error=f"Primary Red planning model unavailable: {exc}",
            )


def get_red_planning_model_options() -> list[RedPlanningModelOption]:
    return list(RED_PLANNING_MODEL_OPTIONS)


def resolve_red_planning_model_option(model_id: Optional[str]) -> RedPlanningModelOption:
    if model_id:
        match = next((option for option in RED_PLANNING_MODEL_OPTIONS if option.model_id == model_id), None)
        if match:
            return match
    return next(
        (option for option in RED_PLANNING_MODEL_OPTIONS if option.model_id == DEFAULT_RED_MODEL_ID),
        RED_PLANNING_MODEL_OPTIONS[0],
    )


def build_red_planning_reasoner(model_id: Optional[str] = None) -> RedPlanningReasoner:
    mode = str(get_runtime_setting("RED_AGENT_REASONER", "auto")).strip().lower()
    heuristic = HeuristicRedPlanningReasoner()
    if mode == "heuristic":
        return heuristic

    selected_option = resolve_red_planning_model_option(model_id)
    base_url = str(get_runtime_setting("OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL)).strip()
    timeout = get_runtime_float("OLLAMA_TIMEOUT_SECONDS", DEFAULT_OLLAMA_TIMEOUT_SECONDS)
    think = get_runtime_bool("OLLAMA_THINK", DEFAULT_OLLAMA_THINK)
    ollama = OllamaRedPlanningReasoner(
        model=selected_option.ollama_model,
        model_id=selected_option.model_id,
        model_label=selected_option.label,
        base_url=base_url,
        timeout_seconds=timeout,
        think=think,
    )
    if mode == "ollama":
        return ollama
    return FallbackRedPlanningReasoner(primary=ollama, fallback=heuristic)
