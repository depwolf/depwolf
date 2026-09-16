"""Allow ``python -m depwolf`` to run exactly like the ``depwolf`` console script."""

import sys

from depwolf.interfaces.cli import main

if __name__ == "__main__":
    sys.exit(main())