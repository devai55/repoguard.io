#!/usr/bin/env python3
"""
RepoGuard - A Python CLI Security Scanner
Scans repositories for potential security issues.
"""

import argparse
import os
import sys
import re
import json
import subprocess
import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List
from datetime import datetime, timedelta


# ANSI Color Codes
class Colors:
    """ANSI escape codes for colored terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    # Foreground colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    
    # Background colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"


class LicenseManager:
    """Manages license validation and usage tracking"""

    # Your secret salt (change this!)
    SECRET_SALT = "repoguard_secret_2024_change_me"

    def __init__(self):
        self.license_file = Path.home() / '.repoguard' / 'license.json'
        self.usage_file = Path.home() / '.repoguard' / 'usage.json'
        self._ensure_config_dir()

    def _ensure_config_dir(self):
        """Create config directory if it doesn't exist"""
        config_dir = Path.home() / '.repoguard'
        config_dir.mkdir(exist_ok=True)

    def generate_license_key(self, email, tier='free', duration_days=30):
        """
        Generate a license key (use this to create keys for customers)

        Args:
            email: Customer email
            tier: 'free', 'pro', or 'enterprise'
            duration_days: License duration

        Returns:
            License key string
        """
        expiry = (datetime.now() + timedelta(days=duration_days)).isoformat()
        data = f"{email}|{tier}|{expiry}"
        signature = hashlib.sha256(f"{data}|{self.SECRET_SALT}".encode()).hexdigest()[:16]

        # Format: EMAIL|TIER|EXPIRY|SIGNATURE
        license_key = f"RG-{signature}"
        license_data = {
            'key': license_key,
            'email': email,
            'tier': tier,
            'expiry': expiry,
            'signature': signature
        }

        return license_key, license_data

    def activate_license(self, license_key, email):
        """
        Activate a license key

        Args:
            license_key: License key from customer
            email: Customer email

        Returns:
            (success: bool, message: str)
        """
        try:
            # Extract signature
            if not license_key.startswith('RG-'):
                return False, "Invalid license key format"

            signature = license_key[3:]

            # Get license data from your database/list
            # For now, validate signature
            test_data = f"{email}|pro|2025-12-31T00:00:00"
            expected_sig = hashlib.sha256(f"{test_data}|{self.SECRET_SALT}".encode()).hexdigest()[:16]

            # In production, look up license in your database
            # For this example, we'll create a valid license
            license_data = {
                'key': license_key,
                'email': email,
                'tier': 'pro',
                'expiry': '2025-12-31T00:00:00',
                'activated_at': datetime.now().isoformat()
            }

            # Save license
            with open(self.license_file, 'w') as f:
                json.dump(license_data, f, indent=2)

            return True, f"License activated! Tier: {license_data['tier']}"

        except Exception as e:
            return False, f"Activation failed: {str(e)}"

    def validate_license(self):
        """
        Check if current license is valid

        Returns:
            (is_valid: bool, tier: str, message: str)
        """
        # Check for license file
        if not self.license_file.exists():
            return True, 'free', 'Free tier (10 scans/month)'

        try:
            with open(self.license_file, 'r') as f:
                license_data = json.load(f)

            # Check expiry
            expiry = datetime.fromisoformat(license_data['expiry'])
            if datetime.now() > expiry:
                return False, 'expired', 'License expired. Please renew.'

            tier = license_data.get('tier', 'free')
            return True, tier, f'Active {tier} license'

        except Exception as e:
            return True, 'free', 'License error - defaulting to free tier'

    def check_usage_limit(self):
        """
        Check if user has exceeded free tier limits

        Returns:
            (can_scan: bool, scans_used: int, scans_remaining: int)
        """
        is_valid, tier, _ = self.validate_license()

        # No limits for paid tiers
        if tier in ['pro', 'enterprise']:
            return True, 0, 999999

        # Free tier: 10 scans per month
        FREE_TIER_LIMIT = 10

        # Load usage data
        if not self.usage_file.exists():
            usage_data = {'scans': [], 'month': datetime.now().strftime('%Y-%m')}
        else:
            with open(self.usage_file, 'r') as f:
                usage_data = json.load(f)

        # Reset if new month
        current_month = datetime.now().strftime('%Y-%m')
        if usage_data.get('month') != current_month:
            usage_data = {'scans': [], 'month': current_month}

        scans_this_month = len(usage_data['scans'])

        if scans_this_month >= FREE_TIER_LIMIT:
            return False, scans_this_month, 0

        return True, scans_this_month, FREE_TIER_LIMIT - scans_this_month

    def record_scan(self):
        """Record a scan for usage tracking"""
        # Load or create usage data
        if not self.usage_file.exists():
            usage_data = {'scans': [], 'month': datetime.now().strftime('%Y-%m')}
        else:
            with open(self.usage_file, 'r') as f:
                usage_data = json.load(f)

        # Reset if new month
        current_month = datetime.now().strftime('%Y-%m')
        if usage_data.get('month') != current_month:
            usage_data = {'scans': [], 'month': current_month}

        # Record scan
        usage_data['scans'].append({
            'timestamp': datetime.now().isoformat()
        })

        # Save
        with open(self.usage_file, 'w') as f:
            json.dump(usage_data, f, indent=2)

    def get_upgrade_message(self):
        """Get upgrade prompt for free users"""
        return """
╔══════════════════════════════════════════════════════════════╗
║              🚀 UPGRADE TO REPOGUARD PRO                     ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  You've reached your free tier limit (10 scans/month)       ║
║                                                              ║
║  REPOGUARD PRO - $99/month                                   ║
║  ✓ Unlimited scans                                          ║
║  ✓ JSON/PDF reports                                         ║
║  ✓ CI/CD integration                                        ║
║  ✓ Email alerts                                             ║
║  ✓ Priority support                                         ║
║                                                              ║
║  👉 Get Pro: https://repoguard.dev/pricing                  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""


@dataclass
class ScanStatistics:
    """Tracks scanning statistics and issues found."""
    files_scanned: int = 0
    directories_scanned: int = 0
    issues_critical: int = 0
    issues_high: int = 0
    issues_medium: int = 0
    issues_low: int = 0
    issues_info: int = 0
    skipped_files: int = 0
    lines_analyzed: int = 0
    
    @property
    def total_issues(self) -> int:
        """Return total number of issues found."""
        return (
            self.issues_critical +
            self.issues_high +
            self.issues_medium +
            self.issues_low +
            self.issues_info
        )
    
    def add_issue(self, severity: str) -> None:
        """Increment issue count for given severity."""
        severity_map = {
            "critical": "issues_critical",
            "high": "issues_high",
            "medium": "issues_medium",
            "low": "issues_low",
            "info": "issues_info",
        }
        attr = severity_map.get(severity.lower())
        if attr:
            setattr(self, attr, getattr(self, attr) + 1)


@dataclass
class Issue:
    """Represents a security issue found during scanning."""
    file_path: str
    line_number: int
    severity: str
    category: str
    message: str
    code_snippet: str = ""
    recommendation: str = ""


class RepoGuard:
    """
    Main RepoGuard security scanner class.
    
    Scans a repository for potential security issues including:
    - Hardcoded secrets and credentials
    - Sensitive file exposures
    - Insecure code patterns
    """
    
    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
        ".php", ".cs", ".cpp", ".c", ".h", ".hpp", ".rs", ".swift",
        ".kt", ".scala", ".sh", ".bash", ".zsh", ".ps1", ".bat",
        ".yaml", ".yml", ".json", ".xml", ".toml", ".ini", ".cfg",
        ".env", ".conf", ".config", ".properties", ".sql"
    }
    
    # Directories to skip
    SKIP_DIRECTORIES = {
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "env", ".env", "dist", "build", ".idea", ".vscode",
        "vendor", "packages", ".tox", ".pytest_cache", ".mypy_cache"
    }
    
    def __init__(self, repo_path: str):
        """
        Initialize RepoGuard with the repository path.
        
        Args:
            repo_path: Path to the repository to scan.
        """
        self.repo_path = Path(repo_path).resolve()
        self.stats = ScanStatistics()
        self.issues: List[Issue] = []
        self.findings = {'secrets': [], 'dependencies': [], 'dangerous_code': [], 'git_history': []}
        self.license_manager = LicenseManager()
        
        # Validate repo path
        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {self.repo_path}")
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {self.repo_path}")
    
    def _print_banner(self) -> None:
        """Print the RepoGuard banner."""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ███████╗██████╗  ██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗  ║
║   ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗ ║
║   ██████╔╝█████╗  ██████╔╝██║   ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║ ║
║   ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║ ║
║   ██║  ██║███████╗██║     ╚██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝ ║
║   ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ║
║                                                              ║
║              🛡️  Security Scanner v1.0.0  🛡️                 ║
╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
        print(banner)
    
    def _print_colored(self, message: str, color: str = Colors.WHITE, bold: bool = False) -> None:
        """
        Print a colored message to the console.
        
        Args:
            message: The message to print.
            color: ANSI color code to use.
            bold: Whether to make the text bold.
        """
        prefix = Colors.BOLD if bold else ""
        print(f"{prefix}{color}{message}{Colors.RESET}")
    
    def _print_info(self, message: str) -> None:
        """
        Print an info message.
        
        Args:
            message: The info message to print.
        """
        print(f"{Colors.BLUE}[ℹ]{Colors.RESET} {message}")
    
    def _print_success(self, message: str) -> None:
        """
        Print a success message.
        
        Args:
            message: The success message to print.
        """
        print(f"{Colors.GREEN}[✓]{Colors.RESET} {message}")
    
    def _print_warning(self, message: str) -> None:
        """
        Print a warning message.
        
        Args:
            message: The warning message to print.
        """
        print(f"{Colors.YELLOW}[⚠]{Colors.RESET} {message}")
    
    def _print_error(self, message: str) -> None:
        """
        Print an error message.
        
        Args:
            message: The error message to print.
        """
        print(f"{Colors.RED}[✗]{Colors.RESET} {message}")
    
    def _print_issue(self, issue: Issue) -> None:
        """
        Print a security issue with appropriate coloring.
        
        Args:
            issue: The Issue object to print.
        """
        severity_colors = {
            "critical": Colors.RED + Colors.BOLD,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.CYAN,
            "info": Colors.BLUE,
        }
        
        color = severity_colors.get(issue.severity.lower(), Colors.WHITE)
        severity_badge = f"{color}[{issue.severity.upper()}]{Colors.RESET}"
        
        print(f"\n  {severity_badge} {Colors.MAGENTA}{issue.category}{Colors.RESET}")
        print(f"    📄 File: {issue.file_path}")
        print(f"    📍 Line: {issue.line_number}")
        print(f"    💬 {issue.message}")
        if issue.code_snippet:
            print(f"    📝 Code: {Colors.YELLOW}{issue.code_snippet[:80]}...{Colors.RESET}" 
                  if len(issue.code_snippet) > 80 
                  else f"    📝 Code: {Colors.YELLOW}{issue.code_snippet}{Colors.RESET}")
    
    def _should_scan_file(self, file_path: Path) -> bool:
        """
        Check if a file should be scanned based on extension.
        
        Args:
            file_path: Path to the file to check.
            
        Returns:
            True if the file should be scanned, False otherwise.
        """
        return file_path.suffix.lower() in self.SCANNABLE_EXTENSIONS
    
    def _should_skip_directory(self, dir_name: str) -> bool:
        """
        Check if a directory should be skipped.
        
        Args:
            dir_name: Name of the directory to check.
            
        Returns:
            True if the directory should be skipped, False otherwise.
        """
        return dir_name in self.SKIP_DIRECTORIES
    
    def _collect_files(self) -> List[Path]:
        """
        Collect all scannable files from the repository.
        
        Walks through the repository directory tree and collects files that should
        be scanned based on their extensions, while skipping directories and files
        that should be excluded.
        
        Returns:
            List of Path objects representing files to scan.
        """
        files = []
        
        for root, dirs, filenames in os.walk(self.repo_path):
            # Remove directories that should be skipped
            dirs[:] = [d for d in dirs if not self._should_skip_directory(d)]
            self.stats.directories_scanned += 1
            
            for filename in filenames:
                file_path = Path(root) / filename
                # Skip the JSON report file to avoid scanning our own output
                if filename == "repoguard-report.json":
                    self.stats.skipped_files += 1
                    continue
                if self._should_scan_file(file_path):
                    files.append(file_path)
                else:
                    self.stats.skipped_files += 1
        
        return files
    
    def _scan_file(self, file_path: Path) -> List[Issue]:
        """
        Scan a single file for security issues.
        
        Args:
            file_path: Path to the file to scan.
            
        Returns:
            List of issues found in the file.
        """
        issues = []
        
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (IOError, OSError, UnicodeDecodeError) as e:
            self._print_warning(f"Could not read file: {file_path} - {e}")
            return issues
        except Exception as e:
            self._print_warning(f"Unexpected error reading file {file_path}: {e}")
            return issues
        
        self.stats.lines_analyzed += len(lines)
        
        relative_path = str(file_path.relative_to(self.repo_path))
        
        # Basic security checks (placeholder for more advanced checks)
        for line_num, line in enumerate(lines, start=1):
            line_lower = line.lower()
            
            # Check for hardcoded passwords
            if any(pattern in line_lower for pattern in ["password=", "password:", "passwd="]):
                if "=" in line or ":" in line:
                    issues.append(Issue(
                        file_path=relative_path,
                        line_number=line_num,
                        severity="high",
                        category="Hardcoded Credentials",
                        message="Potential hardcoded password detected",
                        code_snippet=line.strip()
                    ))
            
            # Check for API keys
            if any(pattern in line_lower for pattern in ["api_key", "apikey", "api-key", "secret_key"]):
                if "=" in line or ":" in line:
                    issues.append(Issue(
                        file_path=relative_path,
                        line_number=line_num,
                        severity="high",
                        category="Hardcoded Secrets",
                        message="Potential hardcoded API key or secret detected",
                        code_snippet=line.strip()
                    ))
            
            # Check for TODO security items
            if "todo" in line_lower and "security" in line_lower:
                issues.append(Issue(
                    file_path=relative_path,
                    line_number=line_num,
                    severity="info",
                    category="Security TODO",
                    message="Security-related TODO comment found",
                    code_snippet=line.strip()
                ))
        
        self.stats.files_scanned += 1
        return issues
    
    def _scan_secrets(self, files: List[Path]) -> None:
        """
        Scan files for hardcoded secrets using regex patterns.
        
        Args:
            files: List of files to scan for secrets.
        """
        secret_patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'API Key': r'api[_-]?key\s*=\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            'Private Key': r'-----BEGIN.*PRIVATE KEY-----',
            'GitHub Token': r'ghp_[A-Za-z0-9]{36}',
            'Password': r'password\s*=\s*["\']([^"\'\s]{8,})["\']',
            'Database URL': r'(?:postgresql|mysql|mongodb|sqlite)://[^:]+:[^@]+@',
        }
        
        recommendations = {
            'AWS Access Key': 'Rotate the key and store in AWS Secrets Manager or environment variables',
            'API Key': 'Move API keys to environment variables or secure vaults',
            'Private Key': 'Never commit private keys to version control',
            'GitHub Token': 'Rotate the token and store securely, never in code',
            'Password': 'Use environment variables or secure password managers',
            'Database URL': 'Store database credentials securely, not in source code',
        }
        
        for file_path in files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (IOError, OSError):
                continue
            
            relative_path = str(file_path.relative_to(self.repo_path))
            
            for line_num, line in enumerate(lines, start=1):
                # Skip comment lines
                stripped = line.strip()
                if (stripped.startswith('#') or 
                    stripped.startswith('//') or 
                    stripped.startswith('/*') or 
                    '/*' in stripped):
                    continue
                
                for secret_type, pattern in secret_patterns.items():
                    matches = re.findall(pattern, line, re.IGNORECASE)
                    if matches:
                        # Extract the matched secret (handle groups)
                        if isinstance(matches[0], tuple):
                            matched = matches[0][0] if matches[0] else str(matches[0])
                        else:
                            matched = matches[0]
                        
                        # Truncate to first 50 chars
                        if len(matched) > 50:
                            matched = matched[:47] + '...'
                        
                        # Add to findings
                        finding = {
                            'severity': 'CRITICAL',
                            'type': secret_type,
                            'file': relative_path,
                            'line': line_num,
                            'matched': matched,
                            'recommendation': recommendations.get(secret_type, 'Remove sensitive data from source code')
                        }
                        self.findings['secrets'].append(finding)
                        
                        # Add to issues for consistency
                        issue = Issue(
                            file_path=relative_path,
                            line_number=line_num,
                            severity='critical',
                            category='Hardcoded Secrets',
                            message=f'Potential {secret_type} detected',
                            code_snippet=line.strip(),
                            recommendation=recommendations.get(secret_type, 'Remove sensitive data from source code')
                        )
                        self.issues.append(issue)
                        
                        # Update stats
                        self.stats.issues_critical += 1
    
    def _check_dependencies(self) -> None:
        """
        Check for vulnerable dependencies in requirements.txt and package.json.
        
        This method performs basic vulnerability checks against hardcoded lists.
        In a production system, this should be extended to call real CVE databases
        like the National Vulnerability Database (NVD) API or services like
        Snyk, Dependabot, or OSS Index for comprehensive vulnerability scanning.
        """
        # Hardcoded vulnerable packages for demonstration
        # In production, replace with API calls to CVE databases
        vulnerable_python_packages = {
            'django': {
                'versions': ['<3.2.20'],
                'cve': 'CVE-2023-43665',
                'description': 'Potential SQL injection vulnerability'
            },
            'flask': {
                'versions': ['<2.3.2'],
                'cve': 'CVE-2023-30861',
                'description': 'Potential path traversal vulnerability'
            },
            'requests': {
                'versions': ['<2.31.0'],
                'cve': 'CVE-2023-32681',
                'description': 'Potential CRLF injection vulnerability'
            },
            'sqlalchemy': {
                'versions': ['<2.0.0'],
                'cve': 'Multiple vulnerabilities',
                'description': 'Various security issues in older versions'
            }
        }
        
        vulnerable_nodejs_packages = {
            'express': {
                'versions': ['<4.18.2'],
                'cve': 'CVE-2022-24999',
                'description': 'Open redirect vulnerability'
            },
            'lodash': {
                'versions': ['<4.17.21'],
                'cve': 'CVE-2021-23337',
                'description': 'Command injection vulnerability'
            }
        }
        
        # Check requirements.txt
        requirements_file = self.repo_path / 'requirements.txt'
        if requirements_file.exists():
            self._check_python_requirements(requirements_file, vulnerable_python_packages)
        
        # Check package.json
        package_file = self.repo_path / 'package.json'
        if package_file.exists():
            self._check_nodejs_dependencies(package_file, vulnerable_nodejs_packages)
    
    def _check_python_requirements(self, req_file: Path, vulnerable_packages: Dict) -> None:
        """
        Check Python requirements.txt for vulnerable packages.
        
        Args:
            req_file: Path to requirements.txt file
            vulnerable_packages: Dict of known vulnerable packages
        """
        try:
            with open(req_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except (IOError, OSError) as e:
            self._print_warning(f"Could not read requirements.txt: {e}")
            return
        
        for line_num, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse package name and version
            # Handle formats like: package==1.0.0, package>=1.0.0, package
            package_name = None
            version_spec = None
            
            # Split on common operators
            for op in ['==', '>=', '<=', '>', '<', '!=', '~=', '===']:
                if op in line:
                    parts = line.split(op, 1)
                    package_name = parts[0].strip()
                    version_spec = op + parts[1].strip()
                    break
            
            if not package_name:
                # No version specified
                package_name = line.split()[0].strip()
            
            # Check if package is vulnerable
            if package_name.lower() in vulnerable_packages:
                vuln_info = vulnerable_packages[package_name.lower()]
                
                # Simple version check (in production, use proper version comparison)
                is_vulnerable = False
                if version_spec:
                    installed_version = self._extract_version_from_spec(version_spec)
                    for vuln_spec in vuln_info['versions']:
                        if self._is_version_vulnerable(installed_version, vuln_spec):
                            is_vulnerable = True
                            break
                else:
                    # No version specified, assume vulnerable if known vuln exists
                    is_vulnerable = True
                
                if is_vulnerable:
                    finding = {
                        'severity': 'HIGH',
                        'type': 'Vulnerable Dependency',
                        'file': str(req_file.relative_to(self.repo_path)),
                        'line': line_num,
                        'package': package_name,
                        'version': version_spec or 'unspecified',
                        'cve': vuln_info['cve'],
                        'description': vuln_info['description'],
                        'recommendation': f'Update {package_name} to a secure version or apply security patches'
                    }
                    self.findings['dependencies'].append(finding)
                    
                    # Add to issues
                    issue = Issue(
                        file_path=str(req_file.relative_to(self.repo_path)),
                        line_number=line_num,
                        severity='high',
                        category='Vulnerable Dependencies',
                        message=f'Vulnerable package {package_name} detected ({vuln_info["cve"]})',
                        code_snippet=line,
                        recommendation=f'Update {package_name} to a secure version'
                    )
                    self.issues.append(issue)
                    self.stats.issues_high += 1
    
    def _check_nodejs_dependencies(self, pkg_file: Path, vulnerable_packages: Dict) -> None:
        """
        Check Node.js package.json for vulnerable dependencies.
        
        Args:
            pkg_file: Path to package.json file
            vulnerable_packages: Dict of known vulnerable packages
        """
        try:
            with open(pkg_file, 'r', encoding='utf-8') as f:
                package_data = json.load(f)
        except (IOError, OSError, json.JSONDecodeError) as e:
            self._print_warning(f"Could not parse package.json: {e}")
            return
        
        # Check dependencies and devDependencies
        deps_to_check = {}
        if 'dependencies' in package_data:
            deps_to_check.update(package_data['dependencies'])
        if 'devDependencies' in package_data:
            deps_to_check.update(package_data['devDependencies'])
        
        for package_name, version in deps_to_check.items():
            if package_name.lower() in vulnerable_packages:
                vuln_info = vulnerable_packages[package_name.lower()]
                
                # Simple version check
                is_vulnerable = False
                for vuln_version in vuln_info['versions']:
                    if self._is_version_vulnerable(version, vuln_version):
                        is_vulnerable = True
                        break
                
                if is_vulnerable:
                    finding = {
                        'severity': 'HIGH',
                        'type': 'Vulnerable Dependency',
                        'file': str(pkg_file.relative_to(self.repo_path)),
                        'line': 0,  # JSON doesn't have line numbers easily
                        'package': package_name,
                        'version': version,
                        'cve': vuln_info['cve'],
                        'description': vuln_info['description'],
                        'recommendation': f'Update {package_name} to a secure version using npm audit fix or yarn audit fix'
                    }
                    self.findings['dependencies'].append(finding)
                    
                    # Add to issues
                    issue = Issue(
                        file_path=str(pkg_file.relative_to(self.repo_path)),
                        line_number=0,
                        severity='high',
                        category='Vulnerable Dependencies',
                        message=f'Vulnerable package {package_name} detected ({vuln_info["cve"]})',
                        code_snippet=f'"{package_name}": "{version}"',
                        recommendation=f'Update {package_name} to a secure version'
                    )
                    self.issues.append(issue)
                    self.stats.issues_high += 1
    
    def _extract_version_from_spec(self, version_spec: str) -> str:
        """
        Extract version number from version specification.
        
        Args:
            version_spec: Version spec like '==1.2.3' or '>=1.0.0'
            
        Returns:
            Version string like '1.2.3'
        """
        # Remove operators
        for op in ['==', '>=', '<=', '>', '<', '!=', '~=', '===']:
            if version_spec.startswith(op):
                return version_spec[len(op):].strip()
        return version_spec.strip()
    
    def _is_version_vulnerable(self, installed_version: str, vuln_spec: str) -> bool:
        """
        Check if installed version is vulnerable based on vulnerability spec.
        
        Args:
            installed_version: Version like '3.2.15'
            vuln_spec: Vulnerability spec like '<3.2.20'
            
        Returns:
            True if version is vulnerable
        """
        try:
            if vuln_spec.startswith('<'):
                vuln_version = vuln_spec[1:]
                # Simple version comparison by splitting on dots
                inst_parts = [int(x) for x in installed_version.split('.')]
                vuln_parts = [int(x) for x in vuln_version.split('.')]
                
                # Pad shorter version with zeros
                max_len = max(len(inst_parts), len(vuln_parts))
                inst_parts.extend([0] * (max_len - len(inst_parts)))
                vuln_parts.extend([0] * (max_len - len(vuln_parts)))
                
                # Compare versions
                return inst_parts < vuln_parts
            elif vuln_spec.startswith('<='):
                vuln_version = vuln_spec[2:]
                inst_parts = [int(x) for x in installed_version.split('.')]
                vuln_parts = [int(x) for x in vuln_version.split('.')]
                max_len = max(len(inst_parts), len(vuln_parts))
                inst_parts.extend([0] * (max_len - len(inst_parts)))
                vuln_parts.extend([0] * (max_len - len(vuln_parts)))
                return inst_parts <= vuln_parts
        except (ValueError, IndexError):
            # If parsing fails, assume vulnerable for safety
            return True
        return False
    
    def _check_dangerous_code(self, files: List[Path]) -> None:
        """
        Check for dangerous code patterns that could lead to security vulnerabilities.
        
        Args:
            files: List of files to scan for dangerous patterns.
        """
        dangerous_patterns = {
            'SQL Injection': {
                'patterns': [
                    r'execute\s*\(\s*.*%.*%.*\)',  # String formatting in SQL execute
                    r'\.execute\s*\(\s*f["\'].*\{.*\}.*["\']',  # f-string in SQL execute
                    r'cursor\.execute\s*\(\s*.*\+.*\)',  # String concatenation in SQL
                ],
                'recommendation': 'Use parameterized queries or prepared statements instead of string formatting'
            },
            'Command Injection': {
                'patterns': [
                    r'os\.system\s*\(\s*.*\+.*\)',  # os.system with concatenation
                    r'subprocess\.call\s*\(\s*.*\+.*\)',  # subprocess.call with concatenation
                    r'os\.popen\s*\(\s*.*\+.*\)',  # os.popen with concatenation
                ],
                'recommendation': 'Use subprocess with a list of arguments instead of string concatenation'
            },
            'Path Traversal': {
                'patterns': [
                    r'open\s*\(\s*.*\+.*\.\./',  # open() with path traversal
                    r'with\s+open\s*\(\s*.*\+.*\.\./',  # with open() with path traversal
                    r'Path\s*\(\s*.*\+.*\.\./',  # Path() with path traversal
                ],
                'recommendation': 'Validate and sanitize file paths, use os.path.join or pathlib for safe path construction'
            },
            'Dangerous Eval': {
                'patterns': [
                    r'\beval\s*\(',  # eval() usage
                    r'\bexec\s*\(',  # exec() usage
                ],
                'recommendation': 'Avoid eval() and exec() as they can execute arbitrary code. Use safer alternatives.'
            },
            'Insecure Random': {
                'patterns': [
                    r'\brandom\.random\s*\(',  # Python random.random()
                    r'Math\.random\s*\(',  # JavaScript Math.random()
                ],
                'recommendation': 'Use cryptographically secure random number generators like secrets module or crypto.randomBytes'
            },
            'Hardcoded Admin': {
                'patterns': [
                    r'username\s*=\s*["\']admin["\']',  # Hardcoded admin username
                    r'user\s*=\s*["\']admin["\']',  # Hardcoded admin user
                    r'admin\s*=\s*True',  # Hardcoded admin flag
                ],
                'recommendation': 'Avoid hardcoding admin credentials. Use proper authentication and authorization systems.'
            }
        }
        
        for file_path in files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (IOError, OSError):
                continue
            
            relative_path = str(file_path.relative_to(self.repo_path))
            
            for line_num, line in enumerate(lines, start=1):
                # Skip comment lines
                stripped = line.strip()
                if (stripped.startswith('#') or 
                    stripped.startswith('//') or 
                    stripped.startswith('/*') or 
                    '/*' in stripped):
                    continue
                
                for vuln_type, vuln_info in dangerous_patterns.items():
                    for pattern in vuln_info['patterns']:
                        if re.search(pattern, line, re.IGNORECASE):
                            finding = {
                                'severity': 'HIGH',
                                'type': vuln_type,
                                'file': relative_path,
                                'line': line_num,
                                'code_snippet': line.strip(),
                                'recommendation': vuln_info['recommendation']
                            }
                            self.findings['dangerous_code'].append(finding)
                            
                            # Add to issues
                            issue = Issue(
                                file_path=relative_path,
                                line_number=line_num,
                                severity='high',
                                category='Dangerous Code Patterns',
                                message=f'{vuln_type} vulnerability detected',
                                code_snippet=line.strip(),
                                recommendation=vuln_info['recommendation']
                            )
                            self.issues.append(issue)
                            self.stats.issues_high += 1
                            break  # Only report once per line per vulnerability type
    
    def _check_git_history(self) -> None:
        """
        Check git history for accidentally committed secrets.
        
        Scans the last 50 commits in all branches for common secret patterns
        that may have been accidentally committed to the repository.
        """
        # Check if this is a git repository
        git_dir = self.repo_path / '.git'
        if not git_dir.exists():
            return  # Not a git repository, skip silently
        
        # Top 5 secret patterns to check in git history
        secret_patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'API Key': r'api[_-]?key\s*=\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            'GitHub Token': r'ghp_[A-Za-z0-9]{36}',
            'Password': r'password\s*=\s*["\']([^"\'\s]{8,})["\']',
            'Private Key': r'-----BEGIN.*PRIVATE KEY-----',
        }
        
        try:
            # Get last 50 commits from all branches
            git_log_cmd = [
                'git', 'log', '--all', '--pretty=format:%H', '-50'
            ]
            
            result = subprocess.run(
                git_log_cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                self._print_warning(f"Failed to get git log: {result.stderr.strip()}")
                return
            
            commits = result.stdout.strip().split('\n')
            if not commits or commits == ['']:
                return  # No commits found
            
            # Check each commit
            for commit_hash in commits:
                if not commit_hash.strip():
                    continue
                
                try:
                    # Get commit diff
                    git_show_cmd = ['git', 'show', commit_hash]
                    
                    result = subprocess.run(
                        git_show_cmd,
                        cwd=self.repo_path,
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=10
                    )
                    
                    if result.returncode != 0:
                        continue  # Skip this commit if we can't get the diff
                    
                    diff_content = result.stdout
                    
                    # Search for secrets in the diff (only in added lines)
                    added_lines = []
                    for line in diff_content.split('\n'):
                        if line.startswith('+') and not line.startswith('+++'):
                            added_lines.append(line[1:])  # Remove the + prefix
                    
                    added_content = '\n'.join(added_lines)
                    
                    # Search for secrets in the added content
                    for secret_type, pattern in secret_patterns.items():
                        matches = re.findall(pattern, added_content, re.IGNORECASE)
                        if matches:
                            # Truncate long matches
                            matched = matches[0] if isinstance(matches[0], str) else str(matches[0])
                            if len(matched) > 50:
                                matched = matched[:47] + '...'
                            
                            finding = {
                                'severity': 'MEDIUM',
                                'type': f'Historical {secret_type}',
                                'commit': commit_hash[:8],
                                'matched': matched,
                                'recommendation': 'Rotate credentials and remove from git history using git filter-branch or BFG Repo-Cleaner'
                            }
                            self.findings['git_history'].append(finding)
                            
                            # Add to issues
                            issue = Issue(
                                file_path=f'commit:{commit_hash[:8]}',
                                line_number=0,
                                severity='medium',
                                category='Git History Secrets',
                                message=f'Historical {secret_type} found in git commit',
                                code_snippet=f'Commit: {commit_hash[:8]} - {matched}',
                                recommendation='Rotate credentials and remove from git history using git filter-branch or BFG Repo-Cleaner'
                            )
                            self.issues.append(issue)
                            self.stats.issues_medium += 1
                            
                except subprocess.TimeoutExpired:
                    continue  # Skip this commit if it takes too long
                except Exception as e:
                    continue  # Skip this commit on any error
                    
        except subprocess.TimeoutExpired:
            self._print_warning("Git log command timed out")
        except Exception as e:
            self._print_warning(f"Error checking git history: {e}")
    
    def _generate_report(self) -> None:
        """
        Generate a comprehensive terminal report of the security scan.
        """
        from datetime import datetime
        
        # ANSI Color codes
        RED = "\033[91m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        BLUE = "\033[94m"
        MAGENTA = "\033[95m"
        CYAN = "\033[96m"
        WHITE = "\033[97m"
        BOLD = "\033[1m"
        RESET = "\033[0m"
        
        # Calculate risk score
        risk_score = (
            self.stats.issues_critical * 10 +
            self.stats.issues_high * 5 +
            self.stats.issues_medium * 2 +
            self.stats.issues_low * 1
        )
        
        # Determine risk level
        if risk_score > 50:
            risk_level = f"{RED}{BOLD}CRITICAL RISK{RESET}"
        elif risk_score > 20:
            risk_level = f"{RED}HIGH RISK{RESET}"
        elif risk_score > 5:
            risk_level = f"{YELLOW}MEDIUM RISK{RESET}"
        else:
            risk_level = f"{GREEN}LOW RISK{RESET}"
        
        # HEADER
        header = f"""
╔{'═' * 78}╗
║{CYAN}{BOLD}{' ' * 25}SECURITY SCAN REPORT{' ' * 25}{RESET}║
╚{'═' * 78}╝

{CYAN}Repository:{RESET} {self.repo_path}
{CYAN}Scan Date:{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{CYAN}Files Scanned:{RESET} {self.stats.files_scanned}
{CYAN}Lines Analyzed:{RESET} {self.stats.lines_analyzed:,}
{CYAN}Directories Scanned:{RESET} {self.stats.directories_scanned}
"""
        print(header)
        
        # SUMMARY
        summary = f"""
{CYAN}{'─' * 20} SCAN SUMMARY {'─' * 20}{RESET}

Security Issues Found:
  {RED}● CRITICAL: {self.stats.issues_critical}{RESET}
  {YELLOW}● HIGH:     {self.stats.issues_high}{RESET}
  {BLUE}● MEDIUM:   {self.stats.issues_medium}{RESET}
  {GREEN}● LOW:      {self.stats.issues_low}{RESET}
  {WHITE}● INFO:     {self.stats.issues_info}{RESET}

{BOLD}Total Issues: {self.stats.total_issues}{RESET}
{BOLD}Risk Score: {risk_score} - {risk_level}{RESET}
"""
        print(summary)
        
        # DETAILED FINDINGS
        print(f"{CYAN}{'─' * 20} DETAILED FINDINGS {'─' * 18}{RESET}\n")
        
        # Secrets (first 10)
        if self.findings['secrets']:
            print(f"{RED}{BOLD}🔐 CRITICAL SECRETS (showing first 10):{RESET}")
            for i, finding in enumerate(self.findings['secrets'][:10]):
                print(f"  {i+1:2d}. {MAGENTA}{finding['type']}{RESET}")
                print(f"      📄 {finding['file']}:{finding['line']}")
                print(f"      💬 {YELLOW}{finding['matched']}{RESET}")
                print(f"      🛠️  {finding['recommendation']}")
                print()
        
        # Dependencies (first 10)
        if self.findings['dependencies']:
            print(f"{YELLOW}{BOLD}📦 VULNERABLE DEPENDENCIES (showing first 10):{RESET}")
            for i, finding in enumerate(self.findings['dependencies'][:10]):
                print(f"  {i+1:2d}. {MAGENTA}{finding['package']}{RESET}")
                print(f"      📄 {finding['file']}")
                print(f"      🚨 {RED}{finding['cve']}{RESET}")
                print(f"      💬 {finding['description']}")
                print(f"      🛠️  {finding['recommendation']}")
                print()
        
        # Dangerous Code (first 5)
        dangerous_issues = [issue for issue in self.issues if issue.category == 'Dangerous Code Patterns']
        if dangerous_issues:
            print(f"{YELLOW}{BOLD}💀 DANGEROUS CODE PATTERNS (showing first 5):{RESET}")
            for i, issue in enumerate(dangerous_issues[:5]):
                print(f"  {i+1:2d}. {MAGENTA}{issue.message}{RESET}")
                print(f"      📄 {issue.file_path}:{issue.line_number}")
                print(f"      💬 {YELLOW}{issue.code_snippet}{RESET}")
                print(f"      🛠️  {issue.recommendation}")
                print()
        
        # Git History (first 5)
        if self.findings['git_history']:
            print(f"{BLUE}{BOLD}📚 GIT HISTORY SECRETS (showing first 5):{RESET}")
            for i, finding in enumerate(self.findings['git_history'][:5]):
                print(f"  {i+1:2d}. {MAGENTA}{finding['type']}{RESET}")
                print(f"      📋 Commit: {finding['commit']}")
                print(f"      💬 {YELLOW}{finding['matched']}{RESET}")
                print(f"      🛠️  {finding['recommendation']}")
                print()
        
        # FOOTER
        footer = f"""
{CYAN}{'═' * 80}{RESET}
{BOLD}RepoGuard v1.0.0{RESET} - Comprehensive Security Scanner
For more information: https://github.com/your-repo/repoguard
{CYAN}{'═' * 80}{RESET}
"""
        print(footer)
    
    def _save_json_report(self) -> None:
        """
        Save a comprehensive JSON report of the security scan.
        
        Creates a detailed JSON file containing all scan metadata, statistics,
        findings, and issues found during the security scan.
        """
        from datetime import datetime
        
        # Calculate risk score
        risk_score = (
            self.stats.issues_critical * 10 +
            self.stats.issues_high * 5 +
            self.stats.issues_medium * 2 +
            self.stats.issues_low * 1
        )
        
        # Determine risk level
        if risk_score > 50:
            risk_level = "CRITICAL"
        elif risk_score > 20:
            risk_level = "HIGH"
        elif risk_score > 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Create comprehensive report dictionary
        report = {
            "scan_metadata": {
                "scan_date": datetime.now().isoformat(),
                "repository_path": str(self.repo_path),
                "scanner_version": "1.0.0",
                "scanner_name": "RepoGuard"
            },
            "scan_statistics": {
                "files_scanned": self.stats.files_scanned,
                "directories_scanned": self.stats.directories_scanned,
                "lines_analyzed": self.stats.lines_analyzed,
                "skipped_files": self.stats.skipped_files,
                "issues_critical": self.stats.issues_critical,
                "issues_high": self.stats.issues_high,
                "issues_medium": self.stats.issues_medium,
                "issues_low": self.stats.issues_low,
                "issues_info": self.stats.issues_info,
                "total_issues": self.stats.total_issues,
                "risk_score": risk_score,
                "risk_level": risk_level
            },
            "findings": {
                "secrets": self.findings['secrets'],
                "dependencies": self.findings['dependencies'],
                "dangerous_code": self.findings['dangerous_code'],
                "git_history": self.findings['git_history']
            },
            "issues": [
                {
                    "file_path": issue.file_path,
                    "line_number": issue.line_number,
                    "severity": issue.severity,
                    "category": issue.category,
                    "message": issue.message,
                    "code_snippet": issue.code_snippet,
                    "recommendation": issue.recommendation
                }
                for issue in self.issues
            ]
        }
        
        # Save to JSON file
        json_file_path = self.repo_path / "repoguard-report.json"
        try:
            with open(json_file_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            print(f"\n{Colors.CYAN}📄 JSON report saved to: {json_file_path}{Colors.RESET}")
            
        except (IOError, OSError) as e:
            self._print_error(f"Failed to save JSON report: {e}")
    
    def _print_summary(self) -> None:
        """Print the scan summary."""
        print(f"\n{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        self._print_colored("📊 SCAN SUMMARY", Colors.CYAN, bold=True)
        print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}\n")
        
        print(f"  📁 Repository: {Colors.WHITE}{self.repo_path}{Colors.RESET}")
        print(f"  📂 Directories scanned: {Colors.WHITE}{self.stats.directories_scanned}{Colors.RESET}")
        print(f"  📄 Files scanned: {Colors.WHITE}{self.stats.files_scanned}{Colors.RESET}")
        print(f"  ⏭️  Files skipped: {Colors.WHITE}{self.stats.skipped_files}{Colors.RESET}")
        
        print(f"\n  {Colors.BOLD}Issues Found:{Colors.RESET}")
        print(f"    {Colors.RED}● Critical: {self.stats.issues_critical}{Colors.RESET}")
        print(f"    {Colors.RED}● High:     {self.stats.issues_high}{Colors.RESET}")
        print(f"    {Colors.YELLOW}● Medium:   {self.stats.issues_medium}{Colors.RESET}")
        print(f"    {Colors.CYAN}● Low:      {self.stats.issues_low}{Colors.RESET}")
        print(f"    {Colors.BLUE}● Info:     {self.stats.issues_info}{Colors.RESET}")
        print(f"    {Colors.WHITE}─────────────────{Colors.RESET}")
        print(f"    {Colors.BOLD}Total:      {self.stats.total_issues}{Colors.RESET}")
        
        # Final status
        print()
        if self.stats.issues_critical > 0 or self.stats.issues_high > 0:
            self._print_error("Security issues require immediate attention!")
        elif self.stats.issues_medium > 0:
            self._print_warning("Some security issues should be reviewed.")
        elif self.stats.total_issues > 0:
            self._print_info("Minor issues found - review when possible.")
        else:
            self._print_success("No security issues detected!")
        
        print(f"\n{Colors.CYAN}{'═' * 60}{Colors.RESET}\n")
    
    def scan(self, output_format: str = "text") -> int:
        """
        Execute the security scan on the repository.
        
        This is the main method that orchestrates all security checks.
        
        Args:
            output_format: Output format for results ("text" or "json")
            
        Returns:
            Exit code: 0 for success with no critical/high issues,
                      1 for critical/high issues found,
                      2 for scan errors.
        """
        try:
            # Check license
            is_valid, tier, message = self.license_manager.validate_license()
            can_scan, scans_used, remaining = self.license_manager.check_usage_limit()
            
            if not can_scan:
                print(self.license_manager.get_upgrade_message())
                return None
            
            if tier == 'free' and remaining <= 3:
                print(f"\n⚠️  {remaining} scans remaining this month\n")
            
            # Record this scan
            self.license_manager.record_scan()
            
            # Show license status
            self._print_banner()
            self._print_info(f"License: {message}")
            if tier == 'free':
                self._print_info(f"Scans used: {scans_used}/10 this month ({remaining} remaining)")
            print()
            
            self._print_info(f"Starting security scan of: {Colors.WHITE}{self.repo_path}{Colors.RESET}")
            print()
            
            # Phase 1: Collect files to scan
            self._print_info("📂 Phase 1: Collecting files to scan...")
            files = self._collect_files()
            self._print_success(f"Found {len(files)} files to scan")
            print()
            
            # Phase 2: Basic file scanning
            self._print_info("🔍 Phase 2: Scanning files for basic security issues...")
            print()
            
            for file_path in files:
                try:
                    file_issues = self._scan_file(file_path)
                    
                    for issue in file_issues:
                        self.issues.append(issue)
                        self.stats.add_issue(issue.severity)
                        self._print_issue(issue)
                except Exception as e:
                    self._print_warning(f"Error scanning file {file_path}: {e}")
                    continue
            
            # Phase 3: Secret scanning
            self._print_info("🔐 Phase 3: Scanning for hardcoded secrets...")
            self._scan_secrets(files)
            
            # Print secret findings
            for finding in self.findings['secrets']:
                print(f"\n  {Colors.RED + Colors.BOLD}[CRITICAL]{Colors.RESET} {Colors.MAGENTA}Hardcoded Secrets{Colors.RESET}")
                print(f"    📄 File: {finding['file']}")
                print(f"    📍 Line: {finding['line']}")
                print(f"    🔍 Type: {finding['type']}")
                print(f"    💬 Matched: {Colors.YELLOW}{finding['matched']}{Colors.RESET}")
                print(f"    🛠️  Recommendation: {finding['recommendation']}")
            
            # Phase 4: Dependency checking
            self._print_info("📦 Phase 4: Checking for vulnerable dependencies...")
            self._check_dependencies()
            
            # Phase 5: Dangerous code pattern detection
            self._print_info("💀 Phase 5: Scanning for dangerous code patterns...")
            self._check_dangerous_code(files)
            
            # Phase 6: Git history scanning
            self._print_info("📚 Phase 6: Checking git history for secrets...")
            self._check_git_history()
            
            # Phase 7: Generate reports
            self._print_info("📊 Phase 7: Generating reports...")
            if output_format == "text":
                self._generate_report()
            elif output_format == "json":
                self._generate_report()  # Still show text report
                self._save_json_report()
            
            # Final summary
            self._print_summary()
            
            # Record the scan for usage tracking
            try:
                license_mgr.record_scan()
            except Exception as e:
                # Don't fail the scan if recording fails
                pass
            
            # Return appropriate exit code
            if self.stats.issues_critical > 0 or self.stats.issues_high > 0:
                return 1
            return 0
            
        except Exception as e:
            self._print_error(f"Scan failed with error: {e}")
            return 2


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="repoguard",
        description="""
RepoGuard - A Python CLI Security Scanner

RepoGuard scans your codebase for potential security vulnerabilities including:
• Hardcoded secrets and credentials
• Vulnerable dependencies
• Dangerous code patterns
• Accidentally committed secrets in git history

The scanner supports both human-readable terminal output and machine-readable JSON export.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan --repo ./my-project
  %(prog)s scan --repo /path/to/repository --format json
  %(prog)s scan --repo . --format text
  %(prog)s license status
  %(prog)s license activate --key RG-1234567890abcdef --email user@example.com

Output Formats:
  text    Human-readable colored terminal output (default)
  json    Machine-readable JSON report saved to repoguard-report.json

Exit Codes:
  0    Success - no critical or high severity issues found
  1    Issues found - critical or high severity issues detected
  2    Scan error - failed to complete the scan
  3    License limit exceeded - upgrade required
  4    License expired - renewal required
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a repository for security issues",
        description="Scan a repository for security vulnerabilities and generate reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  repoguard scan --repo .
  repoguard scan --repo /path/to/project --format json
        """
    )
    scan_parser.add_argument(
        "--repo",
        type=str,
        required=True,
        help="Path to the repository to scan (use '.' for current directory)"
    )
    scan_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Output format: 'text' for colored terminal output, 'json' for JSON report file (default: text)"
    )
    
    # License command
    license_parser = subparsers.add_parser(
        "license",
        help="Manage RepoGuard license",
        description="Manage your RepoGuard license activation and status.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  repoguard license status
  repoguard license activate --key RG-1234567890abcdef --email user@example.com
        """
    )
    license_subparsers = license_parser.add_subparsers(dest="license_command", help="License commands")
    
    # License status
    license_subparsers.add_parser("status", help="Check license status and usage")
    
    # License activate
    activate_parser = license_subparsers.add_parser("activate", help="Activate a license key")
    activate_parser.add_argument("--key", required=True, help="License key to activate")
    activate_parser.add_argument("--email", required=True, help="Your email address")
    
    return parser


def main() -> int:
    """
    Main entry point for RepoGuard.
    
    Parses command line arguments and executes the appropriate command.
    Handles errors gracefully and returns appropriate exit codes.
    
    Returns:
        Exit code: 0 for success, 1 for issues found, 2 for errors,
                   3 for license limit exceeded, 4 for expired license.
    """
    try:
        parser = create_parser()
        args = parser.parse_args()
        
        if args.command is None:
            parser.print_help()
            return 0
        
        if args.command == "scan":
            try:
                # Validate repository path
                repo_path = Path(args.repo).resolve()
                if not repo_path.exists():
                    print(f"{Colors.RED}[✗] Error: Repository path does not exist: {repo_path}{Colors.RESET}", file=sys.stderr)
                    return 2
                if not repo_path.is_dir():
                    print(f"{Colors.RED}[✗] Error: Repository path is not a directory: {repo_path}{Colors.RESET}", file=sys.stderr)
                    return 2
                
                # Initialize scanner and run scan
                scanner = RepoGuard(str(repo_path))
                exit_code = scanner.scan(args.format)
                
                # Handle license-related exit codes
                if exit_code == 3:
                    print(f"\n{Colors.YELLOW}💡 Tip: Run 'repoguard license status' to check your usage{Colors.RESET}")
                elif exit_code == 4:
                    print(f"\n{Colors.YELLOW}💡 Tip: Run 'repoguard license activate --key YOUR_KEY --email your@email.com' to activate a new license{Colors.RESET}")
                
                return exit_code
                
            except ValueError as e:
                print(f"{Colors.RED}[✗] Error: {e}{Colors.RESET}", file=sys.stderr)
                return 2
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[⚠] Scan interrupted by user{Colors.RESET}")
                return 130
            except Exception as e:
                print(f"{Colors.RED}[✗] Unexpected error: {e}{Colors.RESET}", file=sys.stderr)
                return 2
        
        elif args.command == "license":
            license_mgr = LicenseManager()
            
            if args.license_command == "status":
                is_valid, tier, message = license_mgr.validate_license()
                can_scan, used, remaining = license_mgr.check_usage_limit()
                
                print(f"\n{Colors.CYAN}📊 License Status{Colors.RESET}")
                print(f"  Tier: {Colors.BOLD}{tier.upper()}{Colors.RESET}")
                print(f"  Status: {message}")
                if tier == 'free':
                    print(f"  Scans used: {used}/10 this month")
                    print(f"  Remaining: {remaining}")
                print()
                
            elif args.license_command == "activate":
                success, message = license_mgr.activate_license(args.key, args.email)
                if success:
                    print(f"\n{Colors.GREEN}✓ {message}{Colors.RESET}\n")
                else:
                    print(f"\n{Colors.RED}✗ {message}{Colors.RESET}\n")
            else:
                # No license subcommand specified
                license_parser = None
                for action in parser._subparsers._actions:
                    if hasattr(action, 'choices') and 'license' in action.choices:
                        license_parser = action.choices['license']
                        break
                if license_parser:
                    license_parser.print_help()
                return 0
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[⚠] Operation interrupted by user{Colors.RESET}")
        return 130
    except Exception as e:
        print(f"{Colors.RED}[✗] Fatal error: {e}{Colors.RESET}", file=sys.stderr)
        return 2
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
