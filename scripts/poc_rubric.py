"""Kept for older imports: the rubric now lives in backend/triage/rubric.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.triage.rubric import *  # noqa: E402,F401,F403
from backend.triage.rubric import CATEGORIES, DISPOSITIONS, LEVELS, SEVERITY_TABLE, TIERS  # noqa: E402,F401
