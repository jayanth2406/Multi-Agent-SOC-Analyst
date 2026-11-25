"""Kept for older imports: triage features now live in backend/triage/features.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.triage.features import *  # noqa: E402,F401,F403
from backend.triage.features import (  # noqa: E402,F401
    CATEGORY_STAGE, RULE_CATEGORY, Context, Inventory, cmd_tokens, features, provisional, route_one, rules_predict)
