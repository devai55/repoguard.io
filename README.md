# 🛡️ RepoGuard - Automated Code Security Scanner

Find security vulnerabilities before they find you. Scan your code in 60 seconds. Prevent $4.45M breaches. Sleep better at night.

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run a security scan
python repoguard.py scan --repo ./my-project

# Check license status
python repoguard.py license status

# Activate a license
python repoguard.py license activate --key YOUR_KEY --email your@email.com
```

## ✨ Features

- **⚡ Lightning Fast**: Scan 10,000+ files in under 60 seconds
- **🔒 100% Local**: Your code never leaves your machine
- **🔍 200+ Secret Patterns**: Detects AWS keys, GitHub tokens, API keys, passwords, private keys
- **📦 Dependency Scanning**: Checks Python, Node.js, Java, Go packages against CVE databases
- **⚠️ Code Pattern Analysis**: Finds SQL injection, XSS, command injection, and OWASP Top 10 vulnerabilities
- **📊 Multiple Report Formats**: Text, JSON reports
- **💰 Cost Effective**: Replace $4,000/month enterprise tools with 50x cheaper solution

## 📋 Requirements

- Python 3.8+
- No external dependencies (uses only Python standard library)

## 📊 License Tiers

### Free Tier
- 10 scans per month
- Basic secret detection
- Dependency checking
- Text reports
- Community support

### Professional ($99/month)
- Unlimited scans
- All security checks
- JSON reports
- CI/CD integration
- Email alerts
- Priority support

### Enterprise ($999/month)
- Everything in Professional
- Custom security rules
- SOC 2/HIPAA mapping
- SSO integration
- Dedicated support
- SLA guarantee

## 🛠️ Usage Examples

```bash
# Scan current directory
python repoguard.py scan --repo .

# Scan specific repository
python repoguard.py scan --repo /path/to/project

# Generate JSON report
python repoguard.py scan --repo . --format json

# Check license status
python repoguard.py license status

# Activate license
python repoguard.py license activate --key RG-1234567890abcdef --email user@example.com
```

## 📈 Sample Output

```
🛡️  RepoGuard Security Scanner

📁 Scanning: /Users/dev/my-project
🔍 Phase 1: Collecting files... ✓ Done (247 files)
🔐 Phase 2: Scanning for secrets... ✓ Done
📦 Phase 3: Checking dependencies... ✓ Done

======================================================================
📊 SECURITY SCAN REPORT
======================================================================

🎯 FINDINGS SUMMARY:
  ● CRITICAL: 3  ← AWS keys, GitHub tokens
  ● HIGH: 5      ← Vulnerable dependencies
  ● MEDIUM: 2    ← Code quality issues

🔐 SECRETS DETECTED (3)
  [1] ● CRITICAL: AWS Access Key
      File: config/database.yml:23
      Fix: Move to environment variables

🚨 RISK LEVEL: CRITICAL (Score: 65)
   Immediate action required

✓ Report saved to: repoguard-report.json
```

## 🔧 Development

```bash
# Clone the repository
git clone https://github.com/your-repo/repoguard.git
cd repoguard

# Run tests
python -m pytest

# Build documentation
python setup.py build_docs
```

## 📞 Support

- **Documentation**: [docs.repoguard.dev](https://docs.repoguard.dev)
- **GitHub Issues**: [github.com/your-repo/repoguard/issues](https://github.com/your-repo/repoguard/issues)
- **Email Support**: support@repoguard.dev

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

RepoGuard is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

**Built by developers, for developers.** 🛡️