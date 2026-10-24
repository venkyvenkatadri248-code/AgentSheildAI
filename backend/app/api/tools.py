from typing import Dict, Any, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.entities import Agent, ToolCall, User, Conversation
from app.security.gateway import CentralSecurityGateway
from app.agents.agent_tools import execute_tool
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/tools", tags=["Tools"])


class ToolExecuteRequest(BaseModel):
    agent_key: str
    tool_name: str
    arguments: Dict[str, Any]
    conversation_id: Optional[str] = None


@router.post("/execute")
def execute_agent_tool(
    req: ToolExecuteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    agent = db.query(Agent).filter(Agent.key == req.agent_key).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{req.agent_key}' not found")

    if req.conversation_id:
        conv = db.query(Conversation).filter(
            Conversation.id == req.conversation_id,
            Conversation.user_id == current_user.id
        ).first()
        if not conv:
            raise HTTPException(status_code=404, detail="Conversation not found")

    # 1. EVALUATE VIA CENTRAL SECURITY GATEWAY FIRST
    decision = CentralSecurityGateway.evaluate_tool_call(
        db=db,
        actor=current_user,
        agent=agent,
        tool_name=req.tool_name,
        arguments=req.arguments,
        conversation_id=req.conversation_id
    )

    # 2. Check Decision Outcome
    if not decision.allowed:
        # Create ToolCall record showing prevention
        tool_call = ToolCall(
            conversation_id=req.conversation_id or "standalone",
            agent_id=agent.id,
            tool_name=req.tool_name,
            arguments=req.arguments,
            security_decision_id=decision.decision_id,
            status="PENDING_APPROVAL" if decision.requires_approval else "BLOCKED",
            error_message=decision.explanation
        )
        db.add(tool_call)
        db.commit()

        return {
            "status": "pending_approval" if decision.requires_approval else "blocked",
            "decision": decision.dict(),
            "result": None,
            "message": decision.explanation
        }

    # 3. If ALLOWED, Execute in constrained environment
    try:
        raw_result = execute_tool(
            tool_name=req.tool_name,
            arguments=req.arguments,
            db=db,
            actor=current_user
        )
        
        tool_call = ToolCall(
            conversation_id=req.conversation_id or "standalone",
            agent_id=agent.id,
            tool_name=req.tool_name,
            arguments=req.arguments,
            result=raw_result,
            security_decision_id=decision.decision_id,
            status="EXECUTED"
        )
        db.add(tool_call)
        db.commit()

        return {
            "status": "success",
            "decision": decision.dict(),
            "result": raw_result,
            "message": "Tool executed securely after passing security gateway verification."
        }
    except Exception as e:
        tool_call = ToolCall(
            conversation_id=req.conversation_id or "standalone",
            agent_id=agent.id,
            tool_name=req.tool_name,
            arguments=req.arguments,
            status="FAILED",
            error_message=str(e)
        )
        db.add(tool_call)
        db.commit()

        raise HTTPException(status_code=500, detail=f"Tool execution failed: {str(e)}")
