"""Model-backed bounded Red planning reasoners.

These reasoners do not execute attacks. They only help choose an ordering over
the already allowlisted local scenarios so Red can be meaningfully model-backed
while staying constrained to platform-managed targets.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional, Protocol
from urllib import error, request

from ...red_agent_models import AttackScenario
from ...run_models import RunConfig
from ...runtime_settings import get_runtime_bool, get_runtime_float, get_runtime_setting


DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_OLLAMA_TIMEOUT_SECONDS = 120.0
DEFAULT_OLLAMA_THINK = False
DEFAULT_RED_MODEL_ID = "gemma3:4b"


@dataclass(frozen=True)
class RedPlanningModelOption:
    """Selectable Red planning model option."""

    model_id: str
    label: str
    ollama_model: str
    description: str


RED_PLANNING_MODEL_OPTIONS: tuple[RedPlanningModelOption, ...] = (
    RedPlanningModelOption(
        model_id="gemma3:4b",
        label="Gemma 3 4B",
        ollama_model="gemma3:4b",
        description="Compact local planner for bounded Red scenario ordering.",
    ),
    RedPlanningModelOption(
        model_id="deepseek_r1_8b",
        label="DeepSeek R1 8B",
        ollama_model="deepseek-r1:8b",
        description="General reasoning-focused local planner for bounded Red scenario ordering.",
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


@dataclass(frozen=True)
class RedPlanningDecision:
    """Reasoner output for ordered bounded scenario execution."""

    ordered_scenario_ids: list[str]
    rationale: str


class RedPlanningReasoner(Protocol):
    """Interface for model-backed bounded Red planning."""

    @property
    def name(self) -> str:
        """Runtime name for operator-visible logs."""

    @property
    def selected_model_id(self) -> Optional[str]:
        """Stable UI-facing model identifier."""

    @property
    def selected_model_label(self) -> Optional[str]:
        """Human-readable planning model label."""

    def choose_order(self, payload: RedPlanningInput) -> RedPlanningDecision:
        """Return an ordered subset/permutation of already-allowed scenarios."""


class HeuristicRedPlanningReasoner:
    """Deterministic fallback that preserves the existing bounded planner order."""

    name = "heuristic"
    selected_model_id = "heuristic"
    selected_model_label = "Heuristic Planner"

    def choose_order(self, payload: RedPlanningInput) -> RedPlanningDecision:
        return RedPlanningDecision(
            ordered_scenario_ids=[scenario.scenario_id for scenario in payload.candidate_scenarios],
            rationale="Used deterministic bounded planner ordering.",
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
        response_text = self._call_ollama(self._build_prompt(payload))
        parsed = self._parse_response(response_text)
        requested_ids = [str(item).strip() for item in parsed.get("ordered_scenario_ids", [])]
        allowed_ids = [scenario.scenario_id for scenario in payload.candidate_scenarios]
        ordered_ids = [scenario_id for scenario_id in requested_ids if scenario_id in allowed_ids]
        for scenario_id in allowed_ids:
            if scenario_id not in ordered_ids:
                ordered_ids.append(scenario_id)
        return RedPlanningDecision(
            ordered_scenario_ids=ordered_ids,
            rationale=str(parsed.get("rationale", "Used Ollama-backed bounded scenario ordering.")),
        )

    def _build_prompt(self, payload: RedPlanningInput) -> str:
        scenario_lines = [
            f"- {scenario.scenario_id}: {scenario.display_name}. {scenario.description}"
            for scenario in payload.candidate_scenarios
        ]
        return (
            "You are a bounded Red-team planning assistant in a controlled local lab. "
            "You must only reorder the already-allowed local scenarios. "
            "Do not invent new scenarios, commands, payloads, or targets. "
            "Return only a safer, bounded plan order for the existing scenarios.\n\n"
            f"Target name: {payload.target_name}\n"
            f"Target url: {payload.target_url}\n"
            f"Attack depth: {payload.attack_depth}\n"
            f"Duration seconds: {payload.duration_seconds}\n"
            f"Try all available: {payload.try_all_available}\n"
            f"Stop on first confirmed vulnerability: {payload.stop_on_first_confirmed_vulnerability}\n"
            "Allowed scenarios:\n"
            + "\n".join(scenario_lines)
            + "\n\nReturn strict JSON with keys: ordered_scenario_ids, rationale."
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
            "options": {"temperature": 0.1},
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

        parsed = json.loads(body)
        response_text = parsed.get("response")
        if not response_text:
            raise RuntimeError("Ollama returned an empty response payload.")
        return str(response_text)

    def _parse_response(self, response_text: str) -> dict[str, object]:
        payload = json.loads(response_text)
        if not isinstance(payload, dict):
            raise RuntimeError("Ollama planning output was not a JSON object.")
        return payload


class FallbackRedPlanningReasoner:
    """Prefer a primary model-backed planner and fall back cleanly."""

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
                rationale=f"Primary Red planning model unavailable: {exc}. {result.rationale}",
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
