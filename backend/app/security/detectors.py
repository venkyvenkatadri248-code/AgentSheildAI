import re
from typing import Dict, Any, List, Tuple, Optional


class ThreatDetectionResult:
    def __init__(
        self,
        detected: bool,
        category: str,
        severity: str,
        reason: str,
        evidence: Dict[str, Any]
    ):
        self.detected = detected
        self.category = category
        self.severity = severity
        self.reason = reason
        self.evidence = evidence


# Direct Prompt Injection Patterns
PROMPT_INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above|past)\s+(instructions|prompts|rules|commands)", "Instruction override attempt"),
    (r"disregard\s+(all\s+)?(previous|prior|safety|security|all)\s+(rules|guidelines|policies|instructions)", "Safety policy bypass attempt"),
    (r"you\s+are\s+now\s+(in\s+developer\s+mode|dan|unrestricted|jailbroken|evil|unfiltered|an\s+ai\s+without\s+rules)", "Persona hijack / jailbreak attempt"),
    (r"(?:act|pretend|behave)\s+as\s+(?:an\s+unrestricted|a\s+jailbroken|an\s+evil|dan|a\s+hacker|someone\s+without\s+rules)", "Adversarial roleplay jailbreak attempt"),
    (r"(?:reveal|print|show|output|repeat|leak|display)\s+(?:your\s+)?(?:system\s+prompt|core\s+instructions|system\s+instructions|initial\s+prompt|secret\s+key|all\s+rules)", "System prompt / secret exfiltration attempt"),
    (r"what\s+(?:is|are)\s+your\s+(?:exact\s+)?(?:system\s+prompt|core\s+instructions|initial\s+instructions|internal\s+rules)", "System prompt exfiltration query"),
    (r"system:\s*override", "Simulated system message injection"),
    (r"do\s+not\s+follow\s+any\s+(?:safety|rules|instructions|policies)", "Safeguard suppression"),
    (r"bypass\s+(?:the\s+)?(?:security\s+gateway|guardrails|filters|restrictions)", "Security gateway bypass attempt"),
    (r";\s*drop\s+table\s+", "SQL Injection marker"),
    (r"\brm\s+-rf\s+", "Destructive shell command execution marker"),
    (r"\b(curl|wget)\s+http[s]?://", "Arbitrary external network exfiltration marker"),
    (r"\b(?:format\s+[a-z]:|mkfs\b|del\s+\/f\s+\/s)", "Destructive disk formatting command"),
    (r"\b(?:nc|netcat)\s+-[lvpne]", "Reverse shell connection attempt"),
    (r"\[SYSTEM(?:\s+PROMPT)?:\s*OVERRIDE\]", "Bracketed system prompt emulation"),
]

# Indirect Prompt Injection Patterns in untrusted payloads
INDIRECT_INJECTION_PATTERNS = [
    (r"<!--\s*system:\s*ignore\s+instructions\s*-->", "Hidden HTML comment injection"),
    (r"\[SYSTEM\s+PROMPT:\s*override\]", "Bracketed system prompt emulation"),
    (r"AI\s+ASSISTANT\s+NOTICE:\s*Disregard\s+all", "Simulated AI instruction notice"),
    (r"base64:\s*[A-Za-z0-9+/=]{40,}", "Encoded payload payload injection marker"),
    (r"<script[\s\S]*?>[\s\S]*?<\/script>", "Embedded script tag in document"),
]

# Sensitive Data / PII Patterns
SENSITIVE_DATA_PATTERNS = [
    (r"(?<![\w-])(?:\d{4}[ -]?){3}\d{4}(?![\w-])", "CREDIT_CARD", "CRITICAL", "Payment card number detected"),
    (r"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])", "SSN", "CRITICAL", "US Social Security Number detected"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS_ACCESS_KEY", "CRITICAL", "AWS Access Key ID detected"),
    (r"\bAIza[0-9A-Za-z-_]{35}\b", "GOOGLE_API_KEY", "CRITICAL", "Google API Key pattern detected"),
    (r"\bsk-[a-zA-Z0-9]{24,}\b", "API_SECRET_KEY", "CRITICAL", "OpenAI/Platform API Secret key detected"),
    (r"Bearer\s+[a-zA-Z0-9_\-\.]{30,}", "BEARER_TOKEN", "HIGH", "Authorization Bearer token detected"),
    (r"(?:password|passwd|secret)\s*[:=]\s*['\"][^\s'\"]{6,}['\"]", "PLAINTEXT_SECRET", "HIGH", "Plaintext password/secret detected"),
]

# Path Traversal and Dangerous Extensions
PATH_TRAVERSAL_PATTERNS = [
    r"\.\.[\\\/]",
    r"%2e%2e[\\\/]",
    r"[\\\/]etc[\\\/]passwd",
    r"[\\\/]windows[\\\/]system32",
]

DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".dll", ".so", ".bin", ".scr"
}


def detect_direct_prompt_injection(text: str) -> ThreatDetectionResult:
    if not text:
        return ThreatDetectionResult(False, "", "LOW", "", {})
    
    text_lower = text.lower()
    for pattern, reason in PROMPT_INJECTION_PATTERNS:
        match = re.search(pattern, text_lower, re.IGNORECASE)
        if match:
            return ThreatDetectionResult(
                detected=True,
                category="prompt_injection",
                severity="CRITICAL",
                reason=reason,
                evidence={
                    "pattern": pattern,
                    "matched_snippet": match.group(0),
                    "context": text[max(0, match.start() - 20): min(len(text), match.end() + 20)]
                }
            )
    return ThreatDetectionResult(False, "", "LOW", "", {})


def detect_indirect_prompt_injection(content: str, source_name: str = "external_content") -> ThreatDetectionResult:
    if not content:
        return ThreatDetectionResult(False, "", "LOW", "", {})

    for pattern, reason in INDIRECT_INDIRECT_PATTERNS if "INDIRECT_INDIRECT_PATTERNS" in globals() else INDIRECT_INJECTION_PATTERNS:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return ThreatDetectionResult(
                detected=True,
                category="indirect_prompt_injection",
                severity="HIGH",
                reason=f"Indirect injection detected in {source_name}: {reason}",
                evidence={
                    "source": source_name,
                    "pattern": pattern,
                    "matched_snippet": match.group(0)
                }
            )
            
    # Also check direct injection patterns embedded in untrusted external text
    direct_check = detect_direct_prompt_injection(content)
    if direct_check.detected:
        return ThreatDetectionResult(
            detected=True,
            category="indirect_prompt_injection",
            severity="HIGH",
            reason=f"Adversarial instruction found in retrieved content ({source_name})",
            evidence=direct_check.evidence
        )
        
    return ThreatDetectionResult(False, "", "LOW", "", {})


def detect_sensitive_data(payload: Any) -> ThreatDetectionResult:
    text = str(payload) if payload else ""
    if not text:
        return ThreatDetectionResult(False, "", "LOW", "", {})

    # Entity identifiers (UUIDs) are not sensitive card or PII leaks
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", text.strip()):
        return ThreatDetectionResult(False, "", "LOW", "", {})

    for pattern, pii_type, severity, reason in SENSITIVE_DATA_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            matched_val = match.group(0)
            redacted = matched_val[:3] + "*" * (len(matched_val) - 5) + matched_val[-2:] if len(matched_val) > 5 else "***"
            return ThreatDetectionResult(
                detected=True,
                category="sensitive_data_exposure",
                severity=severity,
                reason=reason,
                evidence={
                    "pii_type": pii_type,
                    "redacted_sample": redacted,
                    "position": match.start()
                }
            )
    return ThreatDetectionResult(False, "", "LOW", "", {})


def detect_path_traversal(file_path: str) -> ThreatDetectionResult:
    if not file_path:
        return ThreatDetectionResult(False, "", "LOW", "", {})

    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, file_path, re.IGNORECASE):
            return ThreatDetectionResult(
                detected=True,
                category="dangerous_file_operation",
                severity="HIGH",
                reason="Path traversal sequence detected in file access request",
                evidence={"path": file_path, "pattern": pattern}
            )
            
    import os
    ext = os.path.splitext(file_path)[1].lower()
    if ext in DANGEROUS_EXTENSIONS:
        return ThreatDetectionResult(
            detected=True,
            category="dangerous_file_operation",
            severity="CRITICAL",
            reason=f"Execution of dangerous file format ({ext}) prohibited",
            evidence={"path": file_path, "extension": ext}
        )
        
    return ThreatDetectionResult(False, "", "LOW", "", {})


def detect_unsafe_mail_actions(recipient: str, subject: str, body: str, attachments: Optional[List[str]] = None) -> ThreatDetectionResult:
    # Check for broadcast addresses or suspicious recipients
    unsafe_keywords = ["all@", "everyone@", "company@", "executives@", "broadcast@"]
    for kw in unsafe_keywords:
        if kw in recipient.lower():
            return ThreatDetectionResult(
                detected=True,
                category="unsafe_mail_action",
                severity="HIGH",
                reason=f"Mass distribution recipient '{recipient}' requires strict security approval",
                evidence={"recipient": recipient}
            )
            
    # Check body for sensitive exfiltration
    pii_check = detect_sensitive_data(body)
    if pii_check.detected:
        return ThreatDetectionResult(
                detected=True,
                category="sensitive_data_exposure",
                severity="CRITICAL",
                reason=f"Outbound email contains sensitive data: {pii_check.reason}",
                evidence=pii_check.evidence
            )

    # Check recipient for embedded secrets/tokens
    rec_pii = detect_sensitive_data(recipient)
    if rec_pii.detected:
        return ThreatDetectionResult(
            detected=True,
            category="sensitive_data_exposure",
            severity="CRITICAL",
            reason=f"Recipient field contains sensitive token or data: {rec_pii.reason}",
            evidence=rec_pii.evidence
        )

    # Check prohibited attachments
    if attachments:
        import os
        for att in attachments:
            ext = os.path.splitext(att)[1].lower()
            if ext in DANGEROUS_EXTENSIONS:
                return ThreatDetectionResult(
                    detected=True,
                    category="dangerous_file_operation",
                    severity="CRITICAL",
                    reason=f"Prohibited attachment format '{ext}' in email dispatch",
                    evidence={"attachment": att, "extension": ext}
                )
        
    return ThreatDetectionResult(False, "", "LOW", "", {})


# SSRF and Restricted Networks Patterns
SSRF_PATTERNS = [
    (r"169\.254\.169\.254", "Cloud Instance Metadata Service (IMDS) access attempt"),
    (r"\b(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|0\.0\.0\.0|\[::1\])\b", "Local loopback / private interface access attempt"),
    (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "Private Class A RFC1918 intranet access attempt"),
    (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "Private Class C RFC1918 intranet access attempt"),
    (r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", "Private Class B RFC1918 intranet access attempt"),
    (r"(?:\.corp|\.internal|\.local|\.onion)\b", "Internal enterprise / darknet domain access attempt"),
    (r"https?://[^/]*:[^/]*@", "URL embedded credential exfiltration attempt"),
]


def detect_ssrf_and_restricted_urls(url: str) -> ThreatDetectionResult:
    if not url:
        return ThreatDetectionResult(False, "", "LOW", "", {})
    
    url_lower = url.lower()
    for pattern, reason in SSRF_PATTERNS:
        match = re.search(pattern, url_lower, re.IGNORECASE)
        if match:
            return ThreatDetectionResult(
                detected=True,
                category="unauthorized_network_access",
                severity="CRITICAL" if "169.254" in pattern or "127." in pattern else "HIGH",
                reason=reason,
                evidence={"url": url, "matched_pattern": match.group(0)}
            )
    return ThreatDetectionResult(False, "", "LOW", "", {})


# Protected & Security Configuration Files
PROTECTED_FILES = {
    ".env", ".env.local", ".env.production", "agentshieldai.db", "config.json",
    "settings.py", "docker-compose.yml", "id_rsa", "id_ed25519", "authorized_keys"
}

PROTECTED_PATHS = [
    r"[\\/]etc[\\/](?:passwd|shadow|sudoers)",
    r"[\\/]windows[\\/]system32",
    r"\.git[\\/]",
    r"\.venv[\\/]",
]


def detect_protected_file_target(file_path: str) -> ThreatDetectionResult:
    if not file_path:
        return ThreatDetectionResult(False, "", "LOW", "", {})

    import os
    basename = os.path.basename(file_path.replace("\\", "/")).lower()
    if basename in PROTECTED_FILES or basename.endswith(".pem") or basename.endswith(".key"):
        return ThreatDetectionResult(
            detected=True,
            category="unauthorized_file_modification",
            severity="CRITICAL",
            reason=f"Modification or access to protected security configuration file '{basename}' is strictly prohibited",
            evidence={"file_path": file_path, "protected_target": basename}
        )

    for pattern in PROTECTED_PATHS:
        if re.search(pattern, file_path, re.IGNORECASE):
            return ThreatDetectionResult(
                detected=True,
                category="unauthorized_file_modification",
                severity="CRITICAL",
                reason="Access or modification of sensitive operating system files is prohibited",
                evidence={"file_path": file_path, "pattern": pattern}
            )

    return ThreatDetectionResult(False, "", "LOW", "", {})


# Prohibited Code Execution Patterns
PROHIBITED_CODE_PATTERNS = [
    (r"\b(?:eval|exec)\s*\(", "Dynamic code execution (eval/exec) marker"),
    (r"\bos\.system\s*\(", "Operating system shell execution marker"),
    (r"\bsubprocess\.(?:Popen|run|call|check_output)\s*\(", "Subprocess execution marker"),
    (r"\b__import__\s*\(", "Dynamic module import marker"),
    (r"\bimport\s+(?:os|sys|subprocess|shutil)\b", "Restricted system module import marker"),
    (r"\bshutil\.rmtree\s*\(", "Destructive filesystem operation marker"),
]


def detect_prohibited_code_execution(payload: str) -> ThreatDetectionResult:
    if not payload:
        return ThreatDetectionResult(False, "", "LOW", "", {})

    for pattern, reason in PROHIBITED_CODE_PATTERNS:
        match = re.search(pattern, payload, re.IGNORECASE)
        if match:
            return ThreatDetectionResult(
                detected=True,
                category="prohibited_code_execution",
                severity="CRITICAL",
                reason=reason,
                evidence={"payload_snippet": match.group(0), "pattern": pattern}
            )
    return ThreatDetectionResult(False, "", "LOW", "", {})


# Unapproved Database Modification Patterns
UNAPPROVED_DB_PATTERNS = [
    (r"\bdrop\s+table\b", "DROP TABLE statement detected"),
    (r"\balter\s+table\b", "ALTER TABLE statement detected"),
    (r"\btruncate\s+table\b", "TRUNCATE TABLE statement detected"),
    (r"\bdelete\s+from\b", "DELETE FROM statement detected without authorized transaction"),
    (r"\bupdate\s+\w+\s+set\b", "Direct UPDATE statement detected in read-only analysis context"),
    (r";\s*--", "SQL comment truncation sequence detected"),
    (r"\bunion\s+select\b", "SQL UNION SELECT injection pattern detected"),
]


def detect_unapproved_database_modifications(query: str) -> ThreatDetectionResult:
    if not query:
        return ThreatDetectionResult(False, "", "LOW", "", {})

    for pattern, reason in UNAPPROVED_DB_PATTERNS:
        match = re.search(pattern, query, re.IGNORECASE)
        if match:
            return ThreatDetectionResult(
                detected=True,
                category="unapproved_database_modification",
                severity="CRITICAL",
                reason=reason,
                evidence={"query_snippet": match.group(0), "pattern": pattern}
            )
    return ThreatDetectionResult(False, "", "LOW", "", {})

