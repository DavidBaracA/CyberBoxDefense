"""API router for Blue-agent runtime control."""

from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..blue_agent_models import BlueAgentActionResponse, BlueAgentLogsResponse, BlueAgentState
from ..services.blue_agent_service import BlueAgentService


def create_blue_agent_router(service: BlueAgentService) -> APIRouter:
    """Create the Blue-agent control and streaming router.

    TODO:
    - Add auth and role checks for operator actions if the backend ever leaves localhost.
    - Add richer typed stream events if the terminal grows beyond simple log/status updates.
    """

    router = APIRouter(tags=["blue-agent"])

    @router.get("/blue-agent/status", response_model=BlueAgentState)
    def get_status() -> BlueAgentState:
        return service.status()

    @router.post("/blue-agent/start", response_model=BlueAgentActionResponse)
    def start_agent() -> BlueAgentActionResponse:
        return service.start()

    @router.post("/blue-agent/stop", response_model=BlueAgentActionResponse)
    def stop_agent() -> BlueAgentActionResponse:
        return service.stop()

    @router.get("/blue-agent/logs", response_model=BlueAgentLogsResponse)
    def get_logs() -> BlueAgentLogsResponse:
        return service.logs()

    @router.websocket("/ws/blue-agent")
    async def blue_agent_stream(websocket: WebSocket) -> None:
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
