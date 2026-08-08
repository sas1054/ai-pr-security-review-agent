"""Make ``src`` importable so ``pytest`` works from this directory.

The container image copies ``prsa_control`` next to the orchestrator modules, and CI
sets ``PYTHONPATH=src``. This keeps the documented local command (``cd src/orchestrator
&& pytest``) working without extra environment setup.
"""

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
