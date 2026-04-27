"""
Logging configuration for PDF Forensics Toolkit.

Provides centralized logger setup with consistent formatting across the toolkit.
Supports PDF_FORENSICS_LOG_LEVEL env var and -v/-vv CLI flags.
"""

import logging
import os


# Map verbosity counts to logging levels
_VERBOSITY_LEVELS = {
    0: logging.WARNING,
    1: logging.INFO,
    2: logging.DEBUG,
}

# Map env var values to logging levels
_ENV_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


def configure_logging(verbosity: int = 0) -> None:
    """
    Configure the root pdf_forensics logger based on verbosity or env var.

    Args:
        verbosity: 0=WARNING (default), 1=INFO, 2+=DEBUG
    """
    env_level = os.environ.get("PDF_FORENSICS_LOG_LEVEL", "").upper()
    if env_level in _ENV_LEVELS:
        level = _ENV_LEVELS[env_level]
    else:
        level = _VERBOSITY_LEVELS.get(min(verbosity, 2), logging.DEBUG)

    root_logger = logging.getLogger("pdf_forensics")
    root_logger.setLevel(level)

    if not root_logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)
    else:
        root_logger.handlers[0].setLevel(level)


def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger for the given name.

    Args:
        name: Logger name, typically module name

    Returns:
        Configured logging.Logger instance
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    if logger.level == logging.NOTSET:
        logger.setLevel(logging.WARNING)

    return logger