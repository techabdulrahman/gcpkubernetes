"""Small shared safety helpers for untrusted incident evidence."""

import re


_SECRET_PATTERNS = (
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.S,
    ),
    re.compile(r"(?i)(\bauthorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bglc_[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@"),
    re.compile(
        r"(?im)(\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
        r"client[_-]?secret|secret|password|passwd|credential|authorization|token)"
        r"\b\s*[\"']?\s*[:=]\s*[\"']?)([^\"'\s,;&}]+)"
    ),
)


def redact_sensitive_values(text):
    """Redact common credential formats and values assigned to secret-like keys."""
    redacted = text
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 2:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted
