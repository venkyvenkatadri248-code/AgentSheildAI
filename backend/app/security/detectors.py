import re
from typing import Dict, Any, List, Tuple


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
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "Instruction override attempt"),
    (r"disregard\s+(all\s+)?(previous|safety|security)\s+(rules|guidelines|policies)", "Safety policy bypass attempt"),
    (r"you\s+are\s+now\s+(in\s+developer\s+mode|dan|unrestricted|jailbroken)", "Persona hijack / jailbreak attempt"),
    (r"reveal\s+(your\s+)?(system\s+prompt|core\s+instructions|secret\s+key)", "System prompt / secret exfiltration attempt"),
    (r"system:\s*override", "Simulated system message injection"),
    (r"do\s+not\s+follow\s+any\s+(safety|rules|instructions)", "Safeguard suppression"),
    (r"bypass\s+(the\s+)?(security\s+gateway|guardrails|filters)", "Security gateway bypass attempt"),
    (r";\s*drop\s+table\s+", "SQL Injection marker"),
    (r"\brm\s+-rf\s+", "Destructive shell command execution marker"),
    (r"\b(curl|wget)\s+http[s]?://", "Arbitrary external network exfiltration marker"),
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
    (r"\b(?:\d{4}[ -]?){3}\d{4}\b", "CREDIT_CARD", "CRITICAL", "Payment card number detected"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN", "CRITICAL", "US Social Security Number detected"),
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


def detect_unsafe_mail_actions(recipient: str, subject: str, body: str) -> ThreatDetectionResult:
    # Check for broadcast addresses or suspicious recipients
    unsafe_keywords = ["all@", "everyone@", "company@", "executives@"]
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
        
    return ThreatDetectionResult(False, "", "LOW", "", {})
