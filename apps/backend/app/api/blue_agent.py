"""API router for Blue-agent runtime control."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Body, WebSocket, WebSocketDisconnect

from ..blue_agent_models import (
    BlueAgentActionResponse,
    BlueAgentLogsResponse,
    BlueAgentStartRequest,
    BlueAgentState,
    BlueReasonerOption,
)
from ..services.run_state_store import RunStateStore
from ..services.blue_agent_service import BlueAgentService


def create_blue_agent_router(
    service: BlueAgentService,
    run_state_store: Optional[RunStateStore] = None,
    run_id_provider=None,
) -> APIRouter:
    """Create the Blue-agent control and streaming router.

    TODO:
    - Add auth and role checks for operator actions if the backend ever leaves localhost.
    - Add richer typed stream events if the terminal grows beyond simple log/status updates.
    """

    router = APIRouter(tags=["blue-agent"])

    @router.get("/blue-agent/status", response_model=BlueAgentState)
    def get_status() -> BlueAgentState:
        state = service.status()
        if run_state_store and run_id_provider:
            run_id = run_id_provider()
            if run_id:
                run_state_store.update_blue_status(run_id, state)
        return state

    @router.get("/blue-agent/models", response_model=list[BlueReasonerOption])
    def get_model_options() -> list[BlueReasonerOption]:
        return service.model_options()

    @router.post("/blue-agent/start", response_model=BlueAgentActionResponse)
    def start_agent(
        payload: Optional[BlueAgentStartRequest] = Body(default=None),
    ) -> BlueAgentActionResponse:
        return service.start(payload)

    @router.post("/blue-agent/stop", response_model=BlueAgentActionResponse)
    def stop_agent() -> BlueAgentActionResponse:
        return service.stop()

    @router.get("/blue-agent/logs", response_model=BlueAgentLogsResponse)
    def get_logs() -> BlueAgentLogsResponse:
        if run_state_store and run_id_provider:
            run_id = run_id_provider()
            if run_id:
                run_state_store.update_blue_status(run_id, service.status())
        return service.logs()

    @router.websocket("/ws/blue-agent")
    async def blue_agent_stream(websocket: WebSocket) -> None:
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
