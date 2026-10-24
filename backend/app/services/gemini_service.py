import logging
import json
import asyncio
from typing import AsyncGenerator, List, Dict, Any, Optional
import google.generativeai as genai
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.entities import Agent, Conversation, Message, User
from app.security.gateway import CentralSecurityGateway
from app.agents.agent_tools import execute_tool

logger = logging.getLogger("agentshield.gemini")


class GeminiService:
    @classmethod
    def is_configured(cls) -> bool:
        return bool(settings.GEMINI_API_KEY and settings.GEMINI_API_KEY.strip())

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        configured = cls.is_configured()
        return {
            "configured": configured,
            "model": settings.GEMINI_MODEL,
            "status": "ready" if configured else "missing_api_key",
            "message": "Connected to Google Gen AI" if configured else "GEMINI_API_KEY environment variable is not configured."
        }

    @classmethod
    async def stream_chat_response(
        cls,
        db: Session,
        actor: User,
        conversation: Conversation,
        agent: Agent,
        user_message_content: str,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Stream assistant response chunk-by-chunk.
        Enforces Central Security Gateway before any tool action is triggered.
        """
        # Yield start event
        yield {
            "event": "start",
            "data": {
                "conversation_id": conversation.id,
                "agent_name": agent.name,
                "model": settings.GEMINI_MODEL if cls.is_configured() else "system_notice"
            }
        }

        # Check for direct prompt injection in user input BEFORE even contacting model
        from app.security.detectors import detect_direct_prompt_injection
        det = detect_direct_prompt_injection(user_message_content)
        if det.detected:
            # Block at security boundary!
            decision = CentralSecurityGateway._block_action(
                db=db,
                actor=actor,
                agent=agent,
                decision_id=str(conversation.id),
                tool_name="chat_input",
                risk_category="prompt_injection",
                severity=det.severity,
                policy=None,
                explanation=f"Direct prompt injection detected in input prompt. {det.reason}.",
                evidence=det.evidence,
                conversation_id=conversation.id
            )
            
            notice_text = (
                f"🛡️ **[AgentShieldAI Gateway Intercepted Action]**\n\n"
                f"**Threat Category:** `{decision.risk_category}`\n"
                f"**Severity:** `{decision.severity}`\n"
                f"**Lifecycle State:** `{decision.lifecycle_state}`\n"
                f"**Explanation:** {decision.explanation}\n\n"
                f"*Action was halted at the security perimeter. No downstream systems were accessed.*"
            )
            
            yield {"event": "security_block", "data": decision.dict()}
            yield {"event": "chunk", "data": {"text": notice_text}}
            yield {"event": "done", "data": {"status": "BLOCKED", "tokens": 0}}
            return

        # Handle unconfigured Gemini API key honestly
        if not cls.is_configured():
            warning_msg = (
                f"⚠️ **Google Gemini API Key Not Configured**\n\n"
                f"The backend is operational with full security gateway enforcement, but `GEMINI_API_KEY` is currently not set.\n\n"
                f"To enable live Gemini responses:\n"
                f"1. Obtain an API key from [Google AI Studio](https://aistudio.google.com/).\n"
                f"2. Configure `GEMINI_API_KEY=your_key` in the `.env` file or Settings.\n\n"
                f"*(AgentShieldAI does not fabricate mock LLM completions when upstream API credentials are missing.)*"
            )
            for chunk in [warning_msg[:120], warning_msg[120:250], warning_msg[250:]]:
                await asyncio.sleep(0.04)
                yield {"event": "chunk", "data": {"text": chunk}}
            yield {"event": "done", "data": {"status": "COMPLETED", "tokens": 0}}
            return

        # Configure Gen AI
        genai.configure(api_key=settings.GEMINI_API_KEY)

        # Prepare conversation history
        messages = (
            db.query(Message)
            .filter(Message.conversation_id == conversation.id)
            .order_by(Message.created_at.asc())
            .all()
        )

        history = []
        for m in messages:
            role = "user" if m.sender == "user" else "model"
            if m.content and m.content.strip():
                history.append({"role": role, "parts": [m.content]})

        try:
            model = genai.GenerativeModel(
                model_name=settings.GEMINI_MODEL,
                system_instruction=agent.system_prompt
            )

            # Start chat session
            chat = model.start_chat(history=history[:-1] if history else [])
            
            # Send message with streaming
            response_stream = chat.send_message(user_message_content, stream=True)
            
            accumulated_text = ""
            for chunk in response_stream:
                if chunk.text:
                    accumulated_text += chunk.text
                    yield {"event": "chunk", "data": {"text": chunk.text}}
                    await asyncio.sleep(0.01)

            yield {
                "event": "done",
                "data": {
                    "status": "COMPLETED",
                    "tokens": len(accumulated_text.split()),
                    "full_content": accumulated_text
                }
            }

        except Exception as e:
            logger.error(f"Gemini API streaming error: {e}")
            err_msg = f"❌ Gemini API Error: {str(e)}"
            yield {"event": "error", "data": {"message": err_msg}}
            yield {"event": "chunk", "data": {"text": f"\n\n**Upstream Service Alert:** {err_msg}"}}
            yield {"event": "done", "data": {"status": "FAILED", "tokens": 0}}
