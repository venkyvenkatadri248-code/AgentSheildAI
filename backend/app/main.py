import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.database.session import Base, engine, SessionLocal
from app.database.seed import seed_database
from app.api import (
    auth, agents, conversations, tools, alerts,
    protection, approvals, history, dashboard, files, settings as settings_api, ws
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("agentshield.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure upload directory exists
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    
    # Initialize database tables
    logger.info("Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    
    # Seed default agents, policies, and accounts
    with SessionLocal() as db:
        seed_database(db)

    # Preload threat detection models and fusion engine
    try:
        from app.security.models import (
            DistilBERTThreatDetector,
            BiLSTMSequenceDetector,
            XGBoostEventDetector,
            IsolationForestAnomalyDetector
        )
        logger.info("Preloading AgentShieldAI threat detection models...")
        DistilBERTThreatDetector.load_trained_weights()
        BiLSTMSequenceDetector.load_trained_weights()
        XGBoostEventDetector.load_trained_weights()
        IsolationForestAnomalyDetector.load_trained_weights()
        logger.info("All 4 detection models & MultiModelFusionEngine loaded and ready.")
    except Exception as e:
        logger.warning(f"Model preloading warning: {e}")

    logger.info(f"AgentShieldAI Backend started successfully in {settings.APP_ENV} mode.")
    yield
    logger.info("AgentShieldAI Backend shutting down.")


app = FastAPI(
    title=settings.APP_NAME,
    description="Gemini-Powered AI Agent Security Platform — DETECT · EXPLAIN · PREVENT",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware (allows Vercel, localhost, and any client origins)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers under /api
app.include_router(auth.router, prefix="/api")
app.include_router(agents.router, prefix="/api")
app.include_router(conversations.router, prefix="/api")
app.include_router(tools.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(protection.router, prefix="/api")
app.include_router(approvals.router, prefix="/api")
app.include_router(history.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(files.router, prefix="/api")
app.include_router(settings_api.router, prefix="/api")
app.include_router(ws.router)


@app.get("/health")
def root_health():
    return {"status": "healthy", "service": settings.APP_NAME, "version": "1.0.0"}


@app.get("/")
def root_index():
    return {
        "product": "AgentShieldAI",
        "tagline": "DETECT · EXPLAIN · PREVENT",
        "docs": "/docs",
        "health": "/health"
    }
