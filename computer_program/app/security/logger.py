#logger functions
import logging
from logging.handlers import RotatingFileHandler
import os

def security_logger():
    logger = logging.getLogger("security")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        os.makedirs("logs", exist_ok=True)

        handler = RotatingFileHandler(
            "logs/security.log",
            maxBytes=1000000,
            backupCount=3
        )

        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)

        logger.addHandler(handler)

    return logger