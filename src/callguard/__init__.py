"""CallGuard: answers vulnerability questions about contact-center and UC products."""

import os
from pathlib import Path

from dotenv import load_dotenv


def load_settings():
    """Load the keys from .env. LangSmith is optional: without its key, tracing is switched off, so a fresh copy of
    the project runs quietly with just the Nebius key instead of warning on every question."""
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    if not os.getenv("LANGSMITH_API_KEY"):
        os.environ["LANGSMITH_TRACING"] = "false"
