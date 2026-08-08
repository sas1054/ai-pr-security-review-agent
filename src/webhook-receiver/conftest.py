"""Make ``src`` importable so ``pytest`` works from this directory.

The function app packages ``prsa_control`` alongside the receiver modules, and CI sets
``PYTHONPATH=src``. This keeps the documented local command (``cd src/webhook-receiver
&& pytest``) working without extra environment setup.
"""

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
