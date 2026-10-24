from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.entities import Agent, User
from app.schemas.api_schemas import AgentResponse
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/agents", tags=["Agents"])


@router.get("", response_model=List[AgentResponse])
def list_agents(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    agents = db.query(Agent).filter(Agent.is_active == True).all()
    return agents


@router.get("/{key}", response_model=AgentResponse)
def get_agent_by_key(key: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    agent = db.query(Agent).filter(Agent.key == key).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{key}' not found")
    return agent
