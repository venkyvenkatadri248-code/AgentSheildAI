import json
import logging
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.entities import Conversation, Message, Agent, User
from app.schemas.api_schemas import (
    ConversationCreate, ConversationUpdate, ConversationResponse, MessageResponse, MessageSubmitRequest
)
from app.services.auth_service import get_current_user
from app.services.gemini_service import GeminiService

logger = logging.getLogger("agentshield.conversations")
router = APIRouter(prefix="/conversations", tags=["Conversations"])


@router.post("", response_model=ConversationResponse)
def create_conversation(
    req: ConversationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    agent = db.query(Agent).filter(Agent.key == req.agent_key).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{req.agent_key}' not found")

    conv = Conversation(
        user_id=current_user.id,
        agent_id=agent.id,
        title=req.title or f"{agent.name} Chat"
    )
    db.add(conv)
    db.commit()
    db.refresh(conv)
    return conv


@router.get("", response_model=List[ConversationResponse])
def list_conversations(
    agent_key: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Conversation).filter(Conversation.user_id == current_user.id)
    if agent_key:
        query = query.join(Agent).filter(Agent.key == agent_key)
    return query.order_by(Conversation.updated_at.desc()).all()


@router.get("/{id}", response_model=ConversationResponse)
def get_conversation(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    conv = db.query(Conversation).filter(Conversation.id == id, Conversation.user_id == current_user.id).first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conv


@router.patch("/{id}", response_model=ConversationResponse)
def rename_conversation(
    id: str,
    req: ConversationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    conv = db.query(Conversation).filter(Conversation.id == id, Conversation.user_id == current_user.id).first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    conv.title = req.title.strip() or conv.title
    conv.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(conv)
    return conv


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_conversation(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    conv = db.query(Conversation).filter(Conversation.id == id, Conversation.user_id == current_user.id).first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    db.delete(conv)
    db.commit()
    return None


@router.post("/{id}/messages/stream")
async def send_message_and_stream(
    id: str,
    req: MessageSubmitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    conv = db.query(Conversation).filter(Conversation.id == id, Conversation.user_id == current_user.id).first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    agent = db.query(Agent).filter(Agent.id == conv.agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent associated with conversation not found")

    content = req.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Message content cannot be empty")

    # Persist user message
    user_msg = Message(
        conversation_id=conv.id,
        sender="user",
        content=content,
        execution_status="COMPLETED"
    )
    db.add(user_msg)
    conv.updated_at = datetime.utcnow()
    # Auto-title conversation on first message if default
    if conv.title in ["New Conversation", f"{agent.name} Chat"]:
        conv.title = content[:30] + ("..." if len(content) > 30 else "")
    db.commit()

    async def event_generator():
        accumulated_assistant_text = ""
        final_status = "COMPLETED"

        async for chunk in GeminiService.stream_chat_response(
            db=db,
            actor=current_user,
            conversation=conv,
            agent=agent,
            user_message_content=content
        ):
            event_type = chunk.get("event", "chunk")
            data = chunk.get("data", {})
            if event_type == "chunk":
                accumulated_assistant_text += data.get("text", "")
            elif event_type == "done":
                final_status = data.get("status", "COMPLETED")

            yield f"event: {event_type}\ndata: {json.dumps(data)}\n\n"

        # Persist assistant message in database
        if accumulated_assistant_text.strip():
            assistant_msg = Message(
                conversation_id=conv.id,
                sender="assistant",
                content=accumulated_assistant_text,
                model=agent.key,
                execution_status=final_status
            )
            db.add(assistant_msg)
            db.commit()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
