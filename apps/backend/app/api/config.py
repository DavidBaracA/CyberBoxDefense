"""API router for experiment configuration metadata used by the frontend."""

from __future__ import annotations

from fastapi import APIRouter

from ..config_models import (
    AttackTypeOption,
    ConfigOption,
    RunConfigContract,
    attack_depth_label,
    blue_mode_label,
)
from ..run_models import AttackDepth, BlueMode, RunConfig


DEFAULT_DURATION_OPTIONS = [
    ConfigOption(
        value="180",
        label="3 minutes",
        description="Short validation run favoring quick high-signal techniques.",
    ),
    ConfigOption(
        value="300",
        label="5 minutes",
        description="Compact experiment window for thesis demos.",
    ),
    ConfigOption(
        value="600",
        label="10 minutes",
        description="Balanced default for moderate scenario coverage.",
    ),
    ConfigOption(
        value="900",
        label="15 minutes",
        description="Longer run allowing deeper planned coverage.",
    ),
]


def create_config_router(attack_types_provider, red_model_provider=None) -> APIRouter:
    """Create helper endpoints for React experiment configuration forms."""

    router = APIRouter(prefix="/api/config", tags=["config"])

    def build_attack_type_options() -> list[AttackTypeOption]:
        return [
            AttackTypeOption(
                attack_type=scenario.scenario_id,
                label=scenario.display_name,
                description=scenario.description,
                enabled=scenario.enabled,
                execution_mode=scenario.execution_mode,
                notes=scenario.notes,
            )
            for scenario in attack_types_provider()
        ]

    def build_attack_depth_options() -> list[ConfigOption]:
        descriptions = {
            AttackDepth.QUICK: "Prefer fast, high-signal techniques for short sessions.",
            AttackDepth.BALANCED: "Balance quick checks with moderate exploration depth.",
            AttackDepth.DEEP: "Allow deeper multi-step exploration when time budget permits.",
        }
        return [
            ConfigOption(
                value=depth.value,
                label=attack_depth_label(depth),
                description=descriptions[depth],
            )
            for depth in AttackDepth
        ]

    def build_blue_mode_options() -> list[ConfigOption]:
        descriptions = {
            BlueMode.DETECT_ONLY: "Blue monitors and emits detections only.",
            BlueMode.DETECT_AND_CONTAIN: "Reserve space for future containment decisions.",
        }
        return [
            ConfigOption(
                value=mode.value,
                label=blue_mode_label(mode),
                description=descriptions[mode],
            )
            for mode in BlueMode
        ]

    def build_red_model_options() -> list[ConfigOption]:
        if not red_model_provider:
            return []
        return [
            ConfigOption(
                value=model.model_id,
                label=model.label,
                description=model.description,
                metadata={"ollama_model": model.ollama_model},
            )
            for model in red_model_provider()
        ]

    @router.get("/attack-types", response_model=list[AttackTypeOption])
    def get_attack_types() -> list[AttackTypeOption]:
        return build_attack_type_options()

    @router.get("/blue-modes", response_model=list[ConfigOption])
    def get_blue_modes() -> list[ConfigOption]:
        return build_blue_mode_options()

    @router.get("/attack-depths", response_model=list[ConfigOption])
    def get_attack_depths() -> list[ConfigOption]:
        return build_attack_depth_options()

    @router.get("/durations", response_model=list[ConfigOption])
    def get_duration_options() -> list[ConfigOption]:
        return list(DEFAULT_DURATION_OPTIONS)

    @router.get("/run-form", response_model=RunConfigContract)
    def get_run_form_contract() -> RunConfigContract:
        default_duration = int(DEFAULT_DURATION_OPTIONS[2].value)
        default_attack_types = build_attack_type_options()
        default_attack_type = (
            [default_attack_types[0].attack_type] if default_attack_types else []
        )
        default_config = RunConfig(
            duration_seconds=default_duration,
            enabled_attack_types=default_attack_type,
            try_all_available=False,
            attack_depth=AttackDepth.BALANCED,
            stop_on_first_confirmed_vulnerability=False,
            blue_mode=BlueMode.DETECT_ONLY,
            red_model_id="gemma3:4b",
            graceful_shutdown_seconds=10,
        )
        return RunConfigContract(
            request_example={
                "app_id": "managed-app-id",
                "config": default_config.model_dump(mode="json"),
            },
            default_config=default_config,
            duration_options=list(DEFAULT_DURATION_OPTIONS),
            attack_types=default_attack_types,
            attack_depths=build_attack_depth_options(),
            blue_modes=build_blue_mode_options(),
            red_models=build_red_model_options(),
            validation_notes=[
                "duration_seconds must be greater than 0.",
                "When try_all_available is false, enabled_attack_types must contain at least one attack type.",
                "When try_all_available is true, enabled_attack_types may be empty.",
            ],
        )

    return router
