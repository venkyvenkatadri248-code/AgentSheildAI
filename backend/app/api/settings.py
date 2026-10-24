from typing import Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.session import get_db, check_db_health
from app.models.entities import User
from app.services.auth_service import get_current_user
from app.services.gemini_service import GeminiService

router = APIRouter(prefix="/settings", tags=["Settings & Health"])


@router.get("/health")
def get_system_health(db: Session = Depends(get_db)):
    db_ok = check_db_health()
    gemini_status = GeminiService.get_status()

    return {
        "status": "healthy" if db_ok else "degraded",
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "database": {
            "status": "connected" if db_ok else "disconnected",
            "type": "postgresql" if "postgresql" in settings.DATABASE_URL else "sqlite"
        },
        "gemini": gemini_status,
        "security_gateway": {
            "status": "operational",
            "active_guardrails": [
                "direct_prompt_injection",
                "indirect_prompt_injection",
                "sensitive_data_exposure",
                "path_traversal",
                "tool_authorization",
                "human_approval_workflow"
            ]
        }
    }


@router.get("/profile")
def get_profile(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "created_at": current_user.created_at.isoformat()
    }
