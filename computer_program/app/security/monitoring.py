import re
from time import time

# ============================================================
# Lightweight security monitoring utilities
# ============================================================
# Designed for coursework-scale monitoring.
# Uses in-memory tracking (no persistence, no external services).
# Provides:
# - basic brute-force detection
# - simple malicious payload detection (defense-in-depth)
# ============================================================


# ----------------------------
# Failed login tracker
# ----------------------------
# Stores failed login timestamps per IP address
# Format: { "ip_address": [timestamp, timestamp, ...] }
# Note: resets on application restart (acceptable for coursework)
_FAILED_LOGINS = {}


# ----------------------------
# Suspicious input patterns
# ----------------------------
# Common indicators of:
# - XSS
# - SQL injection
# - Path traversal
# - OS command probing
# These are *not* relied on alone, but used for logging and alerting.
SUSPICIOUS_PATTERNS = [
    r"<\s*script",            # XSS
    r"onerror\s*=",           # XSS event handler
    r"onload\s*=",            # XSS event handler
    r"union\s+select",        # SQL injection
    r"or\s+1\s*=\s*1",        # SQL injection
    r"drop\s+table",          # SQL injection
    r"\.\./",                 # Path traversal
    r"%2e%2e%2f",             # Encoded traversal
    r"/etc/passwd",           # Unix file probing
    r"cmd\.exe",              # Windows command probing
    r"powershell",            # PowerShell probing
]


def looks_malicious(*values: str) -> bool:
    """
    Check whether supplied input values contain suspicious patterns.

    Used for:
    - logging potentially malicious requests
    - detecting obvious attack attempts
    - defense-in-depth (not primary protection)

    Returns:
        True if any suspicious pattern is detected
    """
    joined = " ".join([v or "" for v in values]).lower()
    return any(
        re.search(pattern, joined, flags=re.IGNORECASE)
        for pattern in SUSPICIOUS_PATTERNS
    )


def record_failed_login(ip: str, window_seconds: int = 300) -> int:
    """
    Record a failed login attempt for an IP address.

    Used to:
    - detect brute-force behaviour
    - support security logging and monitoring

    Args:
        ip: Client IP address
        window_seconds: Time window to consider (default: 5 minutes)

    Returns:
        Number of failed attempts within the time window
    """
    now = time()

    # Retrieve existing attempts for IP
    timestamps = _FAILED_LOGINS.get(ip, [])

    # Keep only attempts within the defined time window
    timestamps = [t for t in timestamps if now - t <= window_seconds]

    # Record new failed attempt
    timestamps.append(now)
    _FAILED_LOGINS[ip] = timestamps

    return len(timestamps)