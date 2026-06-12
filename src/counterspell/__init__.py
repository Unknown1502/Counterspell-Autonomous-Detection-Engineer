"""Counterspell — an autonomous detection-engineering system for Splunk."""

from .orchestrator import Orchestrator
from .config import Config

__all__ = ["Orchestrator", "Config"]
__version__ = "0.1.0"
