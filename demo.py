#!/usr/bin/env python3
"""
RepoGuard Demo Script
Shows how to use RepoGuard programmatically
"""

import sys
import os
from pathlib import Path

# Add current directory to path so we can import repoguard
sys.path.insert(0, os.path.dirname(__file__))

from repoguard import RepoGuard

def main():
    """Demo of RepoGuard usage"""

    print("🛡️  RepoGuard Demo")
    print("=" * 50)

    # Initialize scanner
    scanner = RepoGuard(".")

    # Run scan
    print("🔍 Running security scan...")
    exit_code = scanner.scan("text")

    print(f"\n✅ Scan completed with exit code: {exit_code}")
    print("\n💡 Tip: Run 'python repoguard.py license status' to check your usage")

if __name__ == "__main__":
    main()