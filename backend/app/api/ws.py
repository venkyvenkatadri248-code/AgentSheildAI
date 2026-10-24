import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.event_broadcaster import broadcaster

logger = logging.getLogger("agentshield.ws")
router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await broadcaster.connect(websocket)
    try:
        while True:
            # Keep connection alive; clients can send ping messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"type": "pong"}')
    except WebSocketDisconnect:
        broadcaster.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
        broadcaster.disconnect(websocket)
