# ============================================================
# Security logging configuration
# ============================================================
# Provides a dedicated logger for security-related events such as:
# - failed login attempts
# - unauthorised access
# - suspicious or malicious behaviour
#
# Logs are written to a rotating file to prevent uncontrolled
# disk usage and to preserve recent security history.
# ============================================================

import logging
from logging.handlers import RotatingFileHandler
import os


def security_logger():
    """
    Create and return a configured security logger.

    Uses:
    - RotatingFileHandler to limit log file size
    - INFO level to capture security-relevant events
    - A dedicated logger namespace ("security")

    Returns:
        logging.Logger instance
    """
    logger = logging.getLogger("security")
    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers if function is called multiple times
    if not logger.handlers:
        # Ensure log directory exists
        os.makedirs("logs", exist_ok=True)

        # Rotate log file when it reaches ~1MB
        handler = RotatingFileHandler(
            "logs/security.log",
            maxBytes=1_000_000,
            backupCount=3
        )

        # Structured log format (timestamp, severity, message)
        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)

        logger.addHandler(handler)

    return logger