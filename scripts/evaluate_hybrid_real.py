"""Compatibility wrapper for the canonical production-path evaluator.

Use ``scripts/evaluate_production.py`` for new accuracy work. This file remains
so older commands still run without carrying a second hybrid decision
implementation.
"""

from __future__ import annotations

from evaluate_production import main


if __name__ == "__main__":
    main()
