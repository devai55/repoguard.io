# Team Integration Guide

## Quick Start for Teams

This guide helps your team integrate RepoGuard into your development workflow.

## Installation for Teams

### Option 1: Per-Project Installation

```bash
# Install in your project
pip install repoguard-cli

# Run your first scan
repoguard scan --repo .
```

### Option 2: Global Installation

```bash
# Install globally on developer machine
pip install repoguard-cli --user

# Available anywhere
repoguard scan --repo /path/to/project
```

### Option 3: Docker Integration

```dockerfile
FROM python:3.11-slim

RUN pip install repoguard-cli

WORKDIR /app
COPY . .

RUN repoguard scan --repo .
```

---

## Integrating into Your Workflow

### 1. Local Development (Pre-commit Hook)

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
echo "Running RepoGuard security scan..."
repoguard scan --repo . --format text

if [ $? -ne 0 ]; then
  echo "❌ Security issues detected. Fix before committing."
  exit 1
fi
echo "✅ Security check passed"
```

Make executable: `chmod +x .git/hooks/pre-commit`

### 2. CI/CD Pipeline

The workflow is already configured in `.github/workflows/security-scan.yml`

Every PR automatically runs security scan and posts results.

### 3. IDE Integration

#### VS Code

Add to `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "RepoGuard Scan",
      "type": "shell",
      "command": "repoguard scan --repo . --format text",
      "group": "build",
      "presentation": {
        "reveal": "always",
        "panel": "new"
      }
    }
  ]
}
```

#### JetBrains IDEs (IntelliJ, PyCharm, etc.)

Create external tool:
- Program: `repoguard`
- Arguments: `scan --repo $ProjectFileDir$ --format text`
- Working directory: `$ProjectFileDir$`

### 4. Team Communication

#### Slack Integration

Add to your CI/CD workflow:

```yaml
- name: Notify Slack
  if: failure()
  run: |
    curl -X POST ${{ secrets.SLACK_WEBHOOK }} \
      -d '{"text":"🚨 Security scan failed in PR #${{ github.event.number }}"}'
```

#### Email Alerts

```yaml
- name: Email Alert
  if: failure()
  run: |
    mail -s "Security Alert" team@company.com < report.txt
```

---

## Common Team Workflows

### Weekly Security Audits

Create `.github/workflows/weekly-audit.yml`:

```yaml
name: Weekly Security Audit

on:
  schedule:
    - cron: '0 9 * * MON'

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install repoguard-cli
      - run: repoguard scan --repo . --format json > audit-report.json
      - name: Generate Report
        run: |
          echo "Weekly Security Audit" > audit.md
          echo "$(date)" >> audit.md
          jq '.' audit-report.json >> audit.md
      - uses: actions/upload-artifact@v4
        with:
          name: weekly-audit-${{ github.run_id }}
          path: audit.md
```

### Pre-release Security Check

```yaml
name: Pre-Release Check

on:
  workflow_dispatch:

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install repoguard-cli
      - run: repoguard scan --repo . --format json
      - name: Fail on Critical
        run: |
          critical=$(jq '.scan_statistics.issues_critical' repoguard-report.json)
          if [ "$critical" -gt 0 ]; then
            echo "❌ Critical issues found. Cannot release."
            exit 1
          fi
          echo "✅ Release approved"
```

---

## Training Your Team

### What to Look For

RepoGuard detects:

1. **Secrets & Credentials**
   - Hardcoded passwords
   - API keys
   - Private keys
   - Tokens

2. **Vulnerable Code Patterns**
   - SQL injection risks
   - XSS vulnerabilities
   - Command injection
   - Insecure crypto

3. **Dependency Issues**
   - Known vulnerabilities
   - Outdated packages
   - License concerns

4. **Code Quality**
   - Hard-coded IPs
   - Debug code
   - TODO/FIXME security notes

### How to Fix Issues

1. **Read the report** - Each finding includes line number and file
2. **Understand the risk** - Learn what makes it a vulnerability
3. **Apply the fix** - Remove secrets, use secure functions
4. **Test locally** - Run `repoguard scan --repo .` to verify
5. **Commit changes** - Push the secure version

---

## Team Best Practices

### 1. Don't Commit Secrets

❌ **Bad:**
```python
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "super_secret_123"
```

✅ **Good:**
```python
from os import getenv
API_KEY = getenv('API_KEY')
DATABASE_PASSWORD = getenv('DATABASE_PASSWORD')
```

### 2. Use Environment Variables

```bash
# .env (added to .gitignore)
API_KEY=sk-1234567890abcdef
DB_PASSWORD=secret123

# Python
from dotenv import load_dotenv
import os

load_dotenv()
api_key = os.getenv('API_KEY')
```

### 3. Keep Dependencies Updated

```bash
# Check for vulnerable dependencies
pip install -U pip
pip check

# Update packages
pip install --upgrade package-name
```

### 4. Code Review Checklist

Before approving PRs, check:
- [ ] No hardcoded credentials
- [ ] No sensitive data in logs
- [ ] Dependencies are current
- [ ] Security scan passed
- [ ] All comments addressed

---

## FAQs

**Q: Can we disable certain security checks?**
A: Yes, create `.repoguard-config.json` with custom rules

**Q: What if we have false positives?**
A: Mark lines with `# noqa: repoguard` to ignore specific checks

**Q: How often should we scan?**
A: Every PR (automatic) + weekly audits (recommended)

**Q: Who should fix security issues?**
A: The developer who wrote the code (learning opportunity!)

---

## Support

- **Documentation:** https://repoguard.dev/docs
- **Issues:** Report via GitHub Issues
- **Community:** Discuss in team Slack channel
