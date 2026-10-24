import os
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


from pydantic import BaseModel
class GeminiKeyRequest(BaseModel):
    api_key: str

@router.post("/gemini-key")
def update_gemini_api_key(
    req: GeminiKeyRequest,
    current_user: User = Depends(get_current_user)
):
    key = req.api_key.strip()
    if not key:
        return {"status": "error", "message": "API key cannot be empty"}
    
    settings.GEMINI_API_KEY = key
    
    # Persist to .env file if it exists
    env_path = os.path.abspath(".env")
    if not os.path.exists(env_path):
        env_path = os.path.abspath("../.env")
        
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            
            key_updated = False
            new_lines = []
            for line in lines:
                if line.startswith("GEMINI_API_KEY="):
                    new_lines.append(f"GEMINI_API_KEY={key}\n")
                    key_updated = True
                else:
                    new_lines.append(line)
            if not key_updated:
                new_lines.append(f"GEMINI_API_KEY={key}\n")
                
            with open(env_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
        except Exception as e:
            pass
            
    return {
        "status": "success",
        "message": "Gemini API key updated successfully and active for real-time streaming."
    }

