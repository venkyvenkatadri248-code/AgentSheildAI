import os
import io
import json
import logging
from typing import Dict, Any, List, Optional
import pandas as pd
from sqlalchemy.orm import Session

from app.models.entities import UploadedFile, User
from app.security.detectors import detect_indirect_prompt_injection

logger = logging.getLogger("agentshield.tools")


# =====================================================================
# 1. RESEARCH AGENT TOOLS
# =====================================================================
def search_web_sources(query: str) -> Dict[str, Any]:
    """
    Search approved knowledge and web sources for a given query.
    """
    # Deterministic knowledge retrieval simulation for reliable testing & demo
    results = [
        {
            "title": f"Security Analysis: {query.title()}",
            "url": f"https://security-kb.internal.org/research/{query.replace(' ', '-').lower()}",
            "snippet": f"Verified research data regarding {query}. Industry best practices recommend rigorous defense-in-depth, least privilege access, and runtime telemetry.",
            "trusted_source": True
        },
        {
            "title": f"Enterprise Guardrails for {query.title()}",
            "url": f"https://cisa-advisories.example.gov/standards/{query.replace(' ', '-').lower()}",
            "snippet": f"National cybersecurity advisory summary for {query}: Enforce deterministic input validation and central policy gateways.",
            "trusted_source": True
        }
    ]
    return {
        "status": "success",
        "query": query,
        "results_count": len(results),
        "sources": results
    }


def extract_web_content(url: str) -> Dict[str, Any]:
    """
    Extract readable text from a URL and inspect for indirect prompt injection.
    """
    sample_text = (
        f"Document fetched from {url}.\n"
        f"Summary of findings: Multi-agent security architectures require strict isolation "
        f"between language models and underlying operational tools. Continuous monitoring ensures zero-trust compliance."
    )
    
    # Untrusted content safety inspection
    indirect_check = detect_indirect_prompt_injection(sample_text, source_name=url)
    if indirect_check.detected:
        return {
            "status": "security_flagged",
            "url": url,
            "warning": indirect_check.reason,
            "content": "[REDACTED - SUSPICIOUS INSTRUCTIONS DETECTED IN WEBPAGE]"
        }

    return {
        "status": "success",
        "url": url,
        "content_length": len(sample_text),
        "content": sample_text
    }


# =====================================================================
# 2. FILE AGENT TOOLS
# =====================================================================
def list_user_files(db: Session, actor: User) -> Dict[str, Any]:
    """
    List files owned by the authenticated user.
    """
    files = db.query(UploadedFile).filter(UploadedFile.user_id == actor.id).all()
    file_list = [
        {
            "id": f.id,
            "filename": f.original_name,
            "file_type": f.file_type,
            "size_bytes": f.file_size,
            "created_at": f.created_at.isoformat()
        }
        for f in files
    ]
    return {
        "status": "success",
        "total_files": len(file_list),
        "files": file_list
    }


def read_document_content(db: Session, actor: User, file_id: str) -> Dict[str, Any]:
    """
    Read extracted text from an uploaded document belonging to the user.
    """
    f = db.query(UploadedFile).filter(UploadedFile.id == file_id).first()
    if not f:
        return {"status": "error", "message": f"File with ID '{file_id}' not found"}
    if f.user_id != actor.id and actor.role != "admin":
        return {"status": "error", "message": "Access denied: Unauthorized file access"}

    text = f.extracted_text or "No text content available."
    
    # Scan document for indirect prompt injection
    indirect_check = detect_indirect_prompt_injection(text, source_name=f.original_name)
    if indirect_check.detected:
        return {
            "status": "security_alert",
            "file_id": f.id,
            "filename": f.original_name,
            "warning": indirect_check.reason,
            "content": text[:200] + "\n... [TRUNCATED - POTENTIAL INJECTION DETECTED]"
        }

    return {
        "status": "success",
        "file_id": f.id,
        "filename": f.original_name,
        "file_type": f.file_type,
        "content": text
    }


# =====================================================================
# 3. DATA ANALYSIS AGENT TOOLS
# =====================================================================
def inspect_dataset_schema(db: Session, actor: User, file_id: str) -> Dict[str, Any]:
    """
    Inspect tabular dataset schema, column types, and record count.
    """
    f = db.query(UploadedFile).filter(UploadedFile.id == file_id).first()
    if not f:
        return {"status": "error", "message": f"Dataset '{file_id}' not found"}
    if f.user_id != actor.id and actor.role != "admin":
        return {"status": "error", "message": "Access denied to dataset"}

    try:
        # Load CSV or tabular content
        if not os.path.exists(f.storage_path):
            return {"status": "error", "message": "Dataset storage file missing on disk"}
        df = pd.read_csv(f.storage_path)
        schema = {col: str(dtype) for col, dtype in df.dtypes.items()}
        return {
            "status": "success",
            "file_id": file_id,
            "dataset_name": f.original_name,
            "rows": len(df),
            "columns": list(df.columns),
            "column_types": schema,
            "missing_values": df.isnull().sum().to_dict()
        }
    except Exception as e:
        logger.error(f"Error parsing dataset: {e}")
        return {"status": "error", "message": f"Failed to parse dataset: {str(e)}"}


def calculate_descriptive_stats(db: Session, actor: User, file_id: str, columns: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Calculate summary statistics (mean, median, std, min, max) for numeric columns.
    """
    f = db.query(UploadedFile).filter(UploadedFile.id == file_id).first()
    if not f:
        return {"status": "error", "message": f"Dataset '{file_id}' not found"}
    if f.user_id != actor.id and actor.role != "admin":
        return {"status": "error", "message": "Access denied to dataset"}

    try:
        df = pd.read_csv(f.storage_path)
        numeric_df = df.select_dtypes(include=['number'])
        if columns:
            selected_cols = [c for c in columns if c in numeric_df.columns]
            numeric_df = numeric_df[selected_cols]
            
        desc = numeric_df.describe().to_dict()
        return {
            "status": "success",
            "file_id": file_id,
            "statistics": desc,
            "analyzed_columns": list(numeric_df.columns)
        }
    except Exception as e:
        return {"status": "error", "message": f"Calculation failed: {str(e)}"}


# =====================================================================
# 4. MAIL AGENT TOOLS
# =====================================================================
def draft_email(recipient: str, subject: str, body: str) -> Dict[str, Any]:
    """
    Create a structured email draft without dispatching.
    """
    return {
        "status": "draft_created",
        "recipient": recipient,
        "subject": subject,
        "body": body,
        "is_sent": False,
        "notice": "Draft prepared successfully. Outbound transmission requires explicit user authorization."
    }


def send_authorized_email(recipient: str, subject: str, body: str) -> Dict[str, Any]:
    """
    Simulated outbound dispatch for authorized emails that have passed human approval.
    """
    logger.info(f"[MAIL DISPATCH] Sending email to {recipient} with subject '{subject}'")
    return {
        "status": "email_sent",
        "recipient": recipient,
        "subject": subject,
        "sent_at": "now",
        "provider": "AgentShield Secure Mail Gateway",
        "confirmation_id": "MSG-" + os.urandom(4).hex().upper()
    }


# =====================================================================
# TOOL EXECUTION REGISTRY DISPATCHER
# =====================================================================
TOOL_REGISTRY = {
    # Research Agent
    "search_web_sources": search_web_sources,
    "extract_web_content": extract_web_content,
    # File Agent
    "list_user_files": list_user_files,
    "read_document_content": read_document_content,
    # Data Analysis Agent
    "inspect_dataset_schema": inspect_dataset_schema,
    "calculate_descriptive_stats": calculate_descriptive_stats,
    # Mail Agent
    "draft_email": draft_email,
    "send_authorized_email": send_authorized_email,
}


def execute_tool(tool_name: str, arguments: Dict[str, Any], db: Session, actor: User) -> Dict[str, Any]:
    if tool_name not in TOOL_REGISTRY:
        raise ValueError(f"Tool '{tool_name}' not registered in tool execution registry")

    func = TOOL_REGISTRY[tool_name]
    # Inspect parameters and inject db / actor if expected
    import inspect
    sig = inspect.signature(func)
    call_args = {}
    for param_name in sig.parameters:
        if param_name == "db":
            call_args["db"] = db
        elif param_name == "actor":
            call_args["actor"] = actor
        elif param_name in arguments:
            call_args[param_name] = arguments[param_name]

    return func(**call_args)
