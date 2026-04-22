"""API router for Red-agent control and operator-visible runtime streaming."""

from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..red_agent_models import (
    AttackScenario,
    RedAgentActionResponse,
    RedAgentLogsResponse,
    RedReasonerOption,
    RedAgentSessionDetail,
    RedAgentSessionSummary,
    RedAgentStartRequest,
    RedAgentStatus,
)
from ..services.run_state_store import RunStateStore


def create_red_agent_router(service, run_state_store: RunStateStore | None = None) -> APIRouter:
    """Create the bounded Red-agent API router.

    TODO:
    - Add auth if operator actions move beyond localhost.
    - Add typed event schemas for the WebSocket stream if the protocol expands.
    """

    router = APIRouter(tags=["red-agent"])

    @router.get("/red-agent/status", response_model=RedAgentStatus)
    def get_status() -> RedAgentStatus:
        state = service.status()
        if run_state_store and state.run_id:
            run_state_store.update_red_status(state.run_id, state)
        return state

    @router.get("/red-agent/scenarios", response_model=list[AttackScenario])
    def get_scenarios() -> list[AttackScenario]:
        return service.scenarios()

    @router.get("/red-agent/models", response_model=list[RedReasonerOption])
    def get_models() -> list[RedReasonerOption]:
        return service.model_options()

    @router.post("/red-agent/start", response_model=RedAgentActionResponse)
    def start_agent(payload: RedAgentStartRequest) -> RedAgentActionResponse:
        return service.start(payload)

    @router.post("/red-agent/stop", response_model=RedAgentActionResponse)
    def stop_agent() -> RedAgentActionResponse:
        return service.stop()

    @router.get("/red-agent/logs", response_model=RedAgentLogsResponse)
    def get_logs() -> RedAgentLogsResponse:
        if run_state_store:
            state = service.status()
            if state.run_id:
                run_state_store.update_red_status(state.run_id, state)
        return service.logs()

    @router.get("/red-agent/sessions", response_model=list[RedAgentSessionSummary])
    def get_sessions() -> list[RedAgentSessionSummary]:
        return service.list_sessions()

    @router.get("/red-agent/sessions/{session_id}", response_model=RedAgentSessionDetail)
    def get_session(session_id: str) -> RedAgentSessionDetail:
        return service.get_session(session_id)

    @router.websocket("/ws/red-agent")
    async def red_agent_stream(websocket: WebSocket) -> None:
        await websocket.accept()
        subscriber_id = None
        try:
            run_id = websocket.query_params.get("run_id")
            subscriber_id, queue = service.register_stream(run_id=run_id)
            while True:
                message = await queue.get()
                await websocket.send_json(message)
        except WebSocketDisconnect:
            pass
        except Exception:
            await websocket.close(code=1011)
        finally:
            if subscriber_id:
                service.unregister_stream(subscriber_id)

    return router
