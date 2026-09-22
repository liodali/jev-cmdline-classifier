#!/usr/bin/env python3
"""Skill entry point: classify a command with JEV and a fail-closed decision layer.

Run ``python3 classify_command.py --help`` for usage. The implementation lives
in the sibling ``jev_classifier`` package so it can also be imported and tested
directly.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from jev_classifier.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
