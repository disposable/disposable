#!/usr/bin/env python3
"""Backward-compatible shim for disposable email domain generator.

This file provides backward compatibility for existing scripts that import
from disposable.py directly. The actual implementation has been moved to
the disposablehosts package.
"""

import sys
from pathlib import Path

# Add src to path for imports
src_path = Path(__file__).parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Re-export everything from the new package for backward compatibility
from disposablehosts import (
    disposableHostGenerator,
    main,
    remoteData,
)

__all__ = ["disposableHostGenerator", "main", "remoteData"]

if __name__ == "__main__":
    main()
