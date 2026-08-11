"""Compatibility shim — real code lives in depwolf.interfaces.cli."""

import sys

from depwolf.interfaces.cli import build_parser, main

__all__ = ["build_parser", "main"]


if __name__ == "__main__":
    sys.exit(main())
