#!/usr/bin/env python3
"""
Backward-compatibility CLI & server wrapper for BinaryStudio (`binary_viewer.py`).
Delegates directly to `binary_viewer.main()`.
"""

import sys
from binary_viewer import main

if __name__ == "__main__":
    sys.exit(main())
