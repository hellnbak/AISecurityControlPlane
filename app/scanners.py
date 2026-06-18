from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Iterable


@dataclass
class Finding:
    type: str
    severity: str
    description: str

    def to_dict(self):
        return asdict(self)


PATTERNS: list[tuple[str, str, str, re.Pattern]] = [
    (
        "aws_access_key_id",
        "high",
        "Possible AWS access key ID",
        re.compile(r"\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    (
        "private_key",
        "critical",
        "Possible private key material",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----"),
    ),
    (
        "github_token",
        "high",
        "Possible GitHub token",
        re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b"),
    ),
    (
        "slack_token",
        "high",
        "Possible Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    (
        "jwt",
        "medium",
        "Possible JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "ssn",
        "medium",
        "Possible US Social Security Number",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    (
        "credit_card",
        "medium",
        "Possible payment card number",
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    ),
    (
        "email_address",
        "low",
        "Email address detected",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
]

JAILBREAK_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore (all )?(previous|prior|above) instructions", re.I),
    re.compile(r"reveal (your )?(system|developer) prompt", re.I),
    re.compile(r"disregard (the )?(policy|safety|guardrails)", re.I),
    re.compile(r"you are now in developer mode", re.I),
]


def _message_text_parts(obj) -> Iterable[str]:
    if obj is None:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, list):
        for item in obj:
            yield from _message_text_parts(item)
    elif isinstance(obj, dict):
        # Anthropic content blocks usually look like {"type":"text","text":"..."}
        if isinstance(obj.get("text"), str):
            yield obj["text"]
        else:
            for value in obj.values():
                yield from _message_text_parts(value)


def extract_prompt_text(payload: dict) -> str:
    pieces: list[str] = []
    if isinstance(payload.get("system"), str):
        pieces.append(payload["system"])
    for message in payload.get("messages", []) or []:
        pieces.extend(list(_message_text_parts(message.get("content"))))
    return "\n".join(pieces)


def scan_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for finding_type, severity, description, pattern in PATTERNS:
        if pattern.search(text):
            findings.append(Finding(finding_type, severity, description))
    for pattern in JAILBREAK_PATTERNS:
        if pattern.search(text):
            findings.append(
                Finding("prompt_injection_or_jailbreak", "medium", "Possible prompt-injection or jailbreak instruction")
            )
            break
    return findings


def redact_text(text: str) -> str:
    redacted = text
    for finding_type, _severity, _description, pattern in PATTERNS:
        redacted = pattern.sub(f"[REDACTED:{finding_type}]", redacted)
    return redacted
