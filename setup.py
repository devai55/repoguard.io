#!/usr/bin/env python3

from setuptools import setup, find_packages
import os

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="repoguard",
    version="1.0.0",
    author="RepoGuard Team",
    author_email="support@repoguard.dev",
    description="Automated Code Security Scanner - Find security vulnerabilities before they find you",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/repoguard/repoguard",
    project_urls={
        "Homepage": "https://repoguard.dev",
        "Documentation": "https://docs.repoguard.dev",
        "Repository": "https://github.com/repoguard/repoguard",
        "Issues": "https://github.com/repoguard/repoguard/issues",
        "Discussions": "https://github.com/repoguard/repoguard/discussions",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: System :: Systems Administration",
    ],
    keywords="security scanner vulnerabilities secrets detection code-analysis devsecops",
    packages=find_packages(),
    py_modules=["repoguard"],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "repoguard=repoguard:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.950",
        ],
    },
)