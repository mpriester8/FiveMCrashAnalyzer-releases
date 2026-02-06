#!/usr/bin/env python
"""Setup configuration for FiveM Crash Analyzer."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="fivem-crash-analyzer",
    version="1.0.0",
    author="Magikarp",
    author_email="",
    description="Comprehensive forensic tool for analyzing FiveM crash dumps",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/fivem-crash-analyzer",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/fivem-crash-analyzer/issues",
        "Documentation": "https://github.com/yourusername/fivem-crash-analyzer/docs",
        "Source Code": "https://github.com/yourusername/fivem-crash-analyzer",
    },
    packages=find_packages(exclude=["tests", "examples", "docs"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Debuggers",
        "Environment :: Console :: Curses",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "fivem-crash-analyzer=crash_analyzer.analyzer:main",
            "crash-analyzer-cli=crash_analyzer_cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
