"""Minimal LangGraph workflow for the Blue-agent monitoring cycle."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from .reasoner import BlueReasoner, BlueReasonerInput
from .state import BlueAgentGraphState
from .telemetry_adapter import BlueTelemetryAdapter


def build_blue_agent_graph(
    telemetry_adapter: BlueTelemetryAdapter,
    reasoner: BlueReasoner,
) -> Any:
    """Build the LangGraph monitoring cycle for the Blue agent.

    TODO:
    - Add checkpointing and durable execution once experiment replay matters.
    - Split detection emission into a richer subgraph when multi-target support
      and HITL review are added.
    """

    builder = StateGraph(BlueAgentGraphState)

    def initialize_context(state: BlueAgentGraphState) -> BlueAgentGraphState:
        iteration = int(state.get("iteration_count", 0)) + 1
        lines = [
            {
                "level": "info",
                "message": f"LangGraph monitoring cycle {iteration} initialized.",
            }
        ]
        return {
            "iteration_count": iteration,
            "cycle_terminal_lines": lines,
        }

    def select_target(state: BlueAgentGraphState) -> BlueAgentGraphState:
        targets = state.get("available_targets", [])
        if not targets:
            return {
                "selected_target": None,
                "cycle_terminal_lines": state.get("cycle_terminal_lines", []) + [
                    {
                        "level": "warning",
                        "message": "No running target available for Blue-side monitoring.",
                    }
                ],
            }

        selected = sorted(targets, key=lambda item: item.get("created_at") or "")[0]
        lines = state.get("cycle_terminal_lines", []) + [
            {
                "level": "info",
                "message": f"Selected target {selected.get('name', 'unknown-target')} for telemetry review.",
            }
        ]
        return {
            "selected_target": selected,
            "cycle_terminal_lines": lines,
        }

    def ingest_telemetry_snapshot(state: BlueAgentGraphState) -> BlueAgentGraphState:
        selected = state.get("selected_target")
        target_names = []
        if selected:
            name = selected.get("name")
            if name:
                target_names.append(name)
            container_name = selected.get("container_name")
            if container_name and container_name not in target_names:
                target_names.append(container_name)

        snapshot = telemetry_adapter.snapshot_since(
            cursor=int(state.get("telemetry_cursor", 0)),
            target_names=target_names,
        )
        event_count = len(snapshot.events)
        lines = state.get("cycle_terminal_lines", []) + [
            {
                "level": "info",
                "message": f"Ingested {event_count} telemetry event(s) from the Blue-safe snapshot.",
            }
        ]
        if snapshot.observables:
            sample_descriptions = []
            for observable in snapshot.observables[-3:]:
                observable_type = observable.get("observable_type") or "unknown-observable"
                path = observable.get("path") or "unknown-path"
                sample_descriptions.append(f"{observable_type} on {path}")
            lines.append(
                {
                    "level": "info",
                    "message": "Recent observable telemetry: " + "; ".join(sample_descriptions) + ".",
                }
            )
        return {
            "recent_telemetry": snapshot.events,
            "recent_observables": snapshot.observables,
            "telemetry_cursor": snapshot.next_cursor,
            "new_evidence_event_ids": snapshot.evidence_event_ids,
            "cycle_terminal_lines": lines,
        }

    def summarize_anomalies(state: BlueAgentGraphState) -> BlueAgentGraphState:
        observables = state.get("recent_observables", [])
        if not observables:
            return {
                "anomaly_summary": "No new telemetry observed during this cycle.",
                "suspicion_score": 0.05,
                "cycle_terminal_lines": state.get("cycle_terminal_lines", []) + [
                    {
                        "level": "info",
                        "message": "No new telemetry arrived; maintaining low suspicion.",
                    }
                ],
            }

        http_errors = sum(1 for observable in observables if (observable.get("http_status") or 0) >= 500)
        elevated = sum(1 for observable in observables if observable.get("severity") in {"warning", "high"})
        login_churn = sum(
            1
            for observable in observables
            if observable.get("observable_type") in {"login_submit_redirect", "login_page_render"}
        )
        success_navigation = sum(
            1
            for observable in observables
            if observable.get("observable_type") == "post_login_navigation"
        )
        score = min(1.0, (http_errors * 0.18) + (elevated * 0.14) + (login_churn * 0.08) + (success_navigation * 0.12))
        summary = (
            f"Observed {len(observables)} semantic observable(s): {http_errors} HTTP 5xx responses, "
            f"{elevated} elevated-severity events, {login_churn} login-flow anomalies, "
            f"{success_navigation} post-login navigation signals."
        )

        level = "warning" if score >= 0.55 else "info"
        lines = state.get("cycle_terminal_lines", []) + [
            {
                "level": level,
                "message": f"Anomaly summary: {summary}",
            },
            {
                "level": "info",
                "message": f"Reasoning checkpoint: suspicion score updated to {round(score, 2):.2f}.",
            },
        ]
        return {
            "anomaly_summary": summary,
            "suspicion_score": round(score, 2),
            "cycle_terminal_lines": lines,
        }

    def classify_attack(state: BlueAgentGraphState) -> BlueAgentGraphState:
        selected = state.get("selected_target") or {}
        recent_observables = state.get("recent_observables", [])
        message_samples = [observable.get("summary", "") for observable in recent_observables if observable.get("summary")]
        if not message_samples:
            # Temporary demo-friendly bootstrap context so the operator can see a
            # meaningful first LLM response immediately after starting Blue.
            message_samples = [
                "Blue agent monitoring started successfully.",
                "No new telemetry has arrived yet; reason from the current low-signal baseline only.",
                f"Target under observation: {selected.get('name', 'unknown-target')}.",
            ]
        reasoner_result = reasoner.reason(
            BlueReasonerInput(
                target_name=selected.get("name", "unknown-target"),
                anomaly_summary=state.get("anomaly_summary", "No anomaly summary available."),
                recent_event_messages=message_samples,
                suspicion_score=float(state.get("suspicion_score", 0.0)),
                evidence_event_ids=list(state.get("new_evidence_event_ids", [])),
            )
        )
        level = "warning" if reasoner_result.confidence >= 0.65 else "info"
        lines = state.get("cycle_terminal_lines", []) + [
            {
                "level": level,
                "message": (
                    f"Classified likely {reasoner_result.predicted_attack_type} "
                    f"with confidence {reasoner_result.confidence:.2f}."
                ),
            },
            {
                "level": "info",
                "message": f"LLM summary: {reasoner_result.summary}",
            },
        ]
        if state.get("new_evidence_event_ids"):
            lines.append(
                {
                    "level": "info",
                    "message": (
                        "Reasoning checkpoint: correlating evidence ids "
                        f"{', '.join(list(state.get('new_evidence_event_ids', []))[:5])}."
                    ),
                }
            )
        if reasoner_result.evidence:
            lines.append(
                {
                    "level": "info",
                    "message": f"LLM evidence: {reasoner_result.evidence[0]}",
                }
            )
        return {
            "predicted_attack_type": reasoner_result.predicted_attack_type,
            "confidence": round(reasoner_result.confidence, 2),
            "evidence": reasoner_result.evidence,
            "cycle_terminal_lines": lines,
        }

    def emit_detection_candidate(state: BlueAgentGraphState) -> BlueAgentGraphState:
        suspicion_score = float(state.get("suspicion_score", 0.0))
        confidence = float(state.get("confidence", 0.0))
        if suspicion_score < 0.55 or confidence < 0.60:
            return {
                "last_detection": None,
                "cycle_terminal_lines": state.get("cycle_terminal_lines", []) + [
                    {
                        "level": "info",
                        "message": "Threshold not reached; continuing observation without emitting a detection.",
                    }
                ],
            }

        summary = (
            f"Blue agent inferred {state.get('predicted_attack_type', 'anomalous_web_activity')} "
            f"from indirect telemetry with confidence {confidence:.2f}."
        )
        detection = {
            "classification": state.get("predicted_attack_type", "anomalous_web_activity"),
            "confidence": confidence,
            "summary": summary,
            "evidence_event_ids": list(state.get("new_evidence_event_ids", []))[:10],
            "metadata": {
                "agent": "langgraph_blue_agent",
                "suspicion_score": suspicion_score,
                "evidence": list(state.get("evidence", []))[:5],
            },
        }
        lines = state.get("cycle_terminal_lines", []) + [
            {
                "level": "warning",
                "message": "Detection threshold crossed; Blue-side detection candidate prepared.",
            }
        ]
        return {
            "last_detection": detection,
            "cycle_terminal_lines": lines,
        }

    builder.add_node("initialize_context", initialize_context)
    builder.add_node("select_target", select_target)
    builder.add_node("ingest_telemetry_snapshot", ingest_telemetry_snapshot)
    builder.add_node("summarize_anomalies", summarize_anomalies)
    builder.add_node("classify_attack", classify_attack)
    builder.add_node("emit_detection_candidate", emit_detection_candidate)

    builder.add_edge(START, "initialize_context")
    builder.add_edge("initialize_context", "select_target")
    builder.add_edge("select_target", "ingest_telemetry_snapshot")
    builder.add_edge("ingest_telemetry_snapshot", "summarize_anomalies")
    builder.add_edge("summarize_anomalies", "classify_attack")
    builder.add_edge("classify_attack", "emit_detection_candidate")
    builder.add_edge("emit_detection_candidate", END)

    return builder.compile()
