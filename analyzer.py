"""Launcher wrapper to keep top-level script while code lives in package.
"""

from crash_analyzer.analyzer import main as _package_main


def main():
    _package_main()


if __name__ == "__main__":
    main()

