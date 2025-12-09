#!/usr/bin/env python3
"""
Setup script for React2Shell Vulnerability Checker
"""

from setuptools import setup, find_packages
import os

# Read the contents of README.md
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="react2shell-checker",
    version="2.0.0",
    author="Security Team",
    author_email="security@example.com",
    description="React2Shell (CVE-2025-55182) Vulnerability Detector",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/foozio/r2s",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    keywords="security vulnerability react cve scanner",
    python_requires=">=3.6",
    install_requires=[
        "requests>=2.25.1",
        "packaging",
    ],
    extras_require={
        "dev": [
            "pytest>=6.2.0",
            "pytest-mock>=3.6.0",
            "pytest-cov>=2.12.0",
            "black>=21.0.0",
            "flake8>=3.9.0",
            "mypy>=0.900",
            "isort>=5.8.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "react2shell-checker=react2shell_checker_unified:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.md", "*.txt"],
    },
    project_urls={
        "Bug Reports": "https://github.com/foozio/r2s/issues",
        "Source": "https://github.com/foozio/r2s",
        "Documentation": "https://github.com/foozio/r2s#readme",
    },
)