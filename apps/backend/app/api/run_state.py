"""API router for live run-state streaming."""

from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..services.run_service import RunService
from ..services.run_state_stream import RunStateStream


def create_run_state_router(
    run_service: RunService,
    run_state_stream: RunStateStream,
) -> APIRouter:
    """Create a run-scoped WebSocket stream for live dashboard data."""

    router = APIRouter(tags=["run-state"])

    @router.websocket("/ws/run-state")
    async def run_state_socket(websocket: WebSocket) -> None:
        run_id = websocket.query_params.get("run_id")
        if not run_id:
            await websocket.close(code=1008)
            return

        try:
            run_service.get_run(run_id)
        except Exception:
            await websocket.close(code=1008)
            return

        await websocket.accept()
        subscriber_id = None
        try:
            subscriber_id, queue = run_state_stream.register(run_id)
            while True:
                message = await queue.get()
                await websocket.send_json(message)
        except WebSocketDisconnect:
            pass
        except Exception:
            await websocket.close(code=1011)
        finally:
            if subscriber_id:
                run_state_stream.unregister(subscriber_id)

    return router
