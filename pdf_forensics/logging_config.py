"""
Logging configuration for PDF Forensics Toolkit.

Provides centralized logger setup with consistent formatting across the toolkit.
"""

import logging


def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger for the given name.
    
    Args:
        name: Logger name, typically module name
        
    Returns:
        Configured logging.Logger instance
    """
    logger = logging.getLogger(name)
    
    # Only configure if not already configured
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    # Set default level to WARNING if not already set
    if logger.level == logging.NOTSET:
        logger.setLevel(logging.WARNING)
    
    return logger
