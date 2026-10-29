"""Vercel serverless entry point — imports the Flask app from app.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app  # noqa: E402, F401
