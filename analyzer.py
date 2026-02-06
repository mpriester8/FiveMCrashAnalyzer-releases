"""Launcher wrapper to keep top-level script while code lives in package.
"""

import sys
import traceback

# Load .env before any crash_analyzer imports (so FIVEM_SYMBOL_CACHE etc. are set)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def main():
    try:
        from crash_analyzer.analyzer import main as _package_main
        _package_main()
    except Exception as e:
        traceback.print_exc()
        sys.stderr.flush()
        input("\nPress Enter to close...")
        sys.exit(1)


if __name__ == "__main__":
    main()

