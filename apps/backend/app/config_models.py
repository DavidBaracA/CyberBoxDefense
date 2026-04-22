"""Frontend-facing configuration contracts for experiment setup forms.

These models mirror the run configuration domain so the React frontend can
build experiment forms without duplicating backend enum knowledge.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from .run_models import AttackDepth, BlueMode, RunConfig


class ConfigOption(BaseModel):
    """Generic labeled option for dropdown/select style UI controls."""

    value: str
    label: str
    description: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackTypeOption(BaseModel):
    """Selectable attack type option mapped to Red-agent scenarios."""

    attack_type: str
    label: str
    description: str
    enabled: bool = True
    execution_mode: str = "browser"
    notes: Optional[str] = None


class RunConfigContract(BaseModel):
    """Frontend helper contract for building run-configuration forms."""

    request_schema_name: str = "CreateRunRequest"
    config_schema_name: str = "RunConfig"
    request_example: dict[str, Any]
    default_config: RunConfig
    duration_options: list[ConfigOption] = Field(default_factory=list)
    attack_types: list[AttackTypeOption] = Field(default_factory=list)
    attack_depths: list[ConfigOption] = Field(default_factory=list)
    blue_modes: list[ConfigOption] = Field(default_factory=list)
    red_models: list[ConfigOption] = Field(default_factory=list)
    validation_notes: list[str] = Field(default_factory=list)


def attack_depth_label(depth: AttackDepth) -> str:
    if depth == AttackDepth.QUICK:
        return "Quick"
    if depth == AttackDepth.BALANCED:
        return "Balanced"
    return "Deep"


def blue_mode_label(mode: BlueMode) -> str:
    if mode == BlueMode.DETECT_ONLY:
        return "Detect Only"
    return "Detect And Contain"
