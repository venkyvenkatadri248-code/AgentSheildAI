import logging
from sqlalchemy.orm import Session
from app.models.entities import User, Agent, SecurityPolicy, PolicyVersion
from app.services.auth_service import get_password_hash

logger = logging.getLogger("agentshield.seed")


def seed_database(db: Session):
    """
    Idempotent seeding of essential agents, security policies, and default accounts.
    """
    # 1. Seed Default Admin & Analyst Users
    admin_user = db.query(User).filter(User.email == "admin@agentshield.ai").first()
    if not admin_user:
        logger.info("Creating default admin user...")
        admin_user = User(
            email="admin@agentshield.ai",
            hashed_password=get_password_hash("Admin@123456"),
            full_name="Security Admin",
            role="admin",
            is_active=True
        )
        db.add(admin_user)
        db.flush()

    analyst_user = db.query(User).filter(User.email == "analyst@agentshield.ai").first()
    if not analyst_user:
        logger.info("Creating default analyst user...")
        analyst_user = User(
            email="analyst@agentshield.ai",
            hashed_password=get_password_hash("Analyst@123456"),
            full_name="SOC Analyst",
            role="analyst",
            is_active=True
        )
        db.add(analyst_user)
        db.flush()

    # 2. Seed the 4 Core AI Agents
    agents_data = [
        {
            "key": "research_agent",
            "name": "Research Agent",
            "icon": "Search",
            "description": "Explores topics, analyzes research papers, fact checks information, and summarizes findings with verified citations.",
            "allowed_tools": ["search_web_sources", "search_research_papers", "extract_web_content"],
            "system_prompt": (
                "You are a helpful and knowledgeable AI Research Assistant. You assist users with answering questions, "
                "exploring topics, analyzing research papers, and citing trustworthy sources clearly and objectively. "
                "Always communicate in a natural, helpful, conversational tone like Gemini."
            )
        },
        {
            "key": "file_agent",
            "name": "Document Agent",
            "icon": "FileText",
            "description": "Creates, reviews, summarizes, and edits documents, reports, notes, and technical writeups.",
            "allowed_tools": ["list_user_files", "read_document_content", "create_document", "edit_document", "summarize_document"],
            "system_prompt": (
                "You are a helpful AI Document Assistant. You assist users with drafting, reading, summarizing, and editing "
                "documents, reports, and notes. Communicate clearly, maintain document accuracy, and respond in a natural, "
                "friendly conversational tone like Gemini."
            )
        },
        {
            "key": "data_analysis_agent",
            "name": "Data Analysis Agent",
            "icon": "BarChart2",
            "description": "Inspects datasets, calculates summary statistics, checks data hygiene, and explains analytical findings.",
            "allowed_tools": ["inspect_dataset_schema", "calculate_descriptive_stats", "validate_dataset_quality", "generate_data_summary_report"],
            "system_prompt": (
                "You are a helpful AI Data Analysis Assistant. You assist users with exploring datasets, calculating descriptive "
                "statistics, evaluating data quality, and interpreting trends. Explain quantitative concepts clearly and conversationally."
            )
        },
        {
            "key": "mail_agent",
            "name": "Mail Agent",
            "icon": "Mail",
            "description": "Composes professional emails, drafts replies, summarizes conversation threads, and reviews correspondence.",
            "allowed_tools": ["draft_email", "search_mailbox", "summarize_email_thread", "send_authorized_email"],
            "system_prompt": (
                "You are a helpful AI Mail Assistant. You assist users with drafting clear, courteous, and professional emails, "
                "summarizing message threads, and polishing correspondence. Maintain an articulate, warm, and professional tone."
            )
        }
    ]

    for a_data in agents_data:
        agent = db.query(Agent).filter(Agent.key == a_data["key"]).first()
        if not agent:
            logger.info(f"Seeding agent: {a_data['name']}")
            agent = Agent(
                key=a_data["key"],
                name=a_data["name"],
                icon=a_data["icon"],
                description=a_data["description"],
                allowed_tools=a_data["allowed_tools"],
                system_prompt=a_data["system_prompt"],
                is_active=True
            )
            db.add(agent)
        else:
            agent.name = a_data["name"]
            agent.allowed_tools = a_data["allowed_tools"]
            agent.description = a_data["description"]
            agent.system_prompt = a_data["system_prompt"]

    # 3. Seed Security Policies
    policies_data = [
        {
            "name": "Direct Prompt Injection Defense",
            "category": "prompt_injection",
            "risk_level": "CRITICAL",
            "description": "Detects and blocks jailbreaks, instruction overrides, system prompt exfiltration, and persona hijack attempts.",
            "is_enabled": True,
            "requires_approval": False,
            "config": {"strict_mode": True, "block_jailbreaks": True}
        },
        {
            "name": "Sensitive Data & PII Guard",
            "category": "sensitive_data",
            "risk_level": "HIGH",
            "description": "Prevents accidental exposure or exfiltration of credit cards, SSNs, API tokens, passwords, and AWS credentials.",
            "is_enabled": True,
            "requires_approval": False,
            "config": {"redact_in_logs": True, "block_export": True}
        },
        {
            "name": "File System & Path Traversal Guard",
            "category": "file_security",
            "risk_level": "HIGH",
            "description": "Blocks directory traversal attacks, prohibited system file access, and execution of dangerous file formats.",
            "is_enabled": True,
            "requires_approval": False,
            "config": {"prohibit_executables": True, "enforce_ownership": True}
        },
        {
            "name": "Tool Authorization & RBAC Policy",
            "category": "tool_auth",
            "risk_level": "HIGH",
            "description": "Ensures agents only execute explicitly assigned tools and prevents unauthorized tool invocation.",
            "is_enabled": True,
            "requires_approval": False,
            "config": {"enforce_agent_whitelist": True}
        },
        {
            "name": "Outbound Email Dispatch Guard",
            "category": "mail_guard",
            "risk_level": "MEDIUM",
            "description": "Enforces human authorization approval before any outbound email is dispatched to external recipients.",
            "is_enabled": True,
            "requires_approval": True,
            "config": {"tools_requiring_approval": ["send_authorized_email"]}
        }
    ]

    for p_data in policies_data:
        pol = db.query(SecurityPolicy).filter(SecurityPolicy.name == p_data["name"]).first()
        if not pol:
            logger.info(f"Seeding policy: {p_data['name']}")
            pol = SecurityPolicy(
                name=p_data["name"],
                category=p_data["category"],
                risk_level=p_data["risk_level"],
                description=p_data["description"],
                is_enabled=p_data["is_enabled"],
                requires_approval=p_data["requires_approval"],
                config=p_data["config"],
                version=1
            )
            db.add(pol)
            db.flush()
            
            # Initial policy version record
            ver = PolicyVersion(
                policy_id=pol.id,
                version=1,
                changed_by="system_initializer",
                changes_summary="Initial policy baseline configuration",
                snapshot=p_data
            )
            db.add(ver)

    db.commit()

    # 4. Clean up any legacy baseline mock telemetry so dashboard strictly tracks live agent actions
    cleanup_baseline_mock_telemetry(db)

    db.commit()
    logger.info("Database seeding completed successfully. Dashboard is strictly tied to real agent actions.")


def cleanup_baseline_mock_telemetry(db: Session):
    """
    Purges any pre-seeded baseline mock telemetry so that the dashboard
    exclusively reflects live, real-time agent actions.
    """
    from app.models.entities import Conversation, ToolCall, SecurityEvent, Alert

    mock_titles = [
        "File Security & Document Verification Session",
        "Data Analytics & Metrics Exploration",
        "Research Web Exploration Session",
        "Executive Email Communication Session"
    ]
    mock_convs = db.query(Conversation).filter(Conversation.title.in_(mock_titles)).all()
    mock_conv_ids = [c.id for c in mock_convs]

    mock_events = db.query(SecurityEvent).filter(
        (SecurityEvent.conversation_id.in_(mock_conv_ids)) | (SecurityEvent.decision_id.like("dec-%"))
    ).all()
    mock_event_ids = [e.id for e in mock_events]

    if mock_event_ids:
        db.query(Alert).filter(Alert.security_event_id.in_(mock_event_ids)).delete(synchronize_session=False)
        db.query(SecurityEvent).filter(SecurityEvent.id.in_(mock_event_ids)).delete(synchronize_session=False)

    if mock_conv_ids:
        db.query(ToolCall).filter(ToolCall.conversation_id.in_(mock_conv_ids)).delete(synchronize_session=False)
        db.query(Conversation).filter(Conversation.id.in_(mock_conv_ids)).delete(synchronize_session=False)

    db.commit()


