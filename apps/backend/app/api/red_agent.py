"""API router for Red-agent control and operator-visible runtime streaming."""

from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..red_agent_models import (
    AttackScenario,
    RedAgentActionResponse,
    RedAgentLogsResponse,
    RedAgentStartRequest,
    RedAgentStatus,
)


def create_red_agent_router(service) -> APIRouter:
    """Create the bounded Red-agent API router.

    TODO:
    - Add auth if operator actions move beyond localhost.
    - Add typed event schemas for the WebSocket stream if the protocol expands.
    """

    router = APIRouter(tags=["red-agent"])

    @router.get("/red-agent/status", response_model=RedAgentStatus)
    def get_status() -> RedAgentStatus:
        return service.status()

    @router.get("/red-agent/scenarios", response_model=list[AttackScenario])
    def get_scenarios() -> list[AttackScenario]:
        return service.scenarios()

    @router.post("/red-agent/start", response_model=RedAgentActionResponse)
    def start_agent(payload: RedAgentStartRequest) -> RedAgentActionResponse:
        return service.start(payload)

    @router.post("/red-agent/stop", response_model=RedAgentActionResponse)
    def stop_agent() -> RedAgentActionResponse:
        return service.stop()

    @router.get("/red-agent/logs", response_model=RedAgentLogsResponse)
    def get_logs() -> RedAgentLogsResponse:
        return service.logs()

    @router.websocket("/ws/red-agent")
    async def red_agent_stream(websocket: WebSocket) -> None:
        await websocket.accept()
        subscriber_id = None
        try:
            subscriber_id, queue = service.register_stream()
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
