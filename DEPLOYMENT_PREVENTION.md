# Deployment Prevention & Build Gates

## Preventing Vulnerable Code from Deployment

This guide shows how to use RepoGuard to prevent insecure code from reaching production.

---

## Build Gates Strategy

### Severity-Based Gates

```yaml
# In your CI/CD workflow
- name: Check Security Gates
  run: |
    # Fail on any CRITICAL issues
    CRITICAL=$(jq '.scan_statistics.issues_critical' repoguard-report.json)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "❌ Cannot deploy: $CRITICAL critical issues found"
      exit 1
    fi
    
    # Warn on HIGH issues (don't fail)
    HIGH=$(jq '.scan_statistics.issues_high' repoguard-report.json)
    if [ "$HIGH" -gt 0 ]; then
      echo "⚠️ WARNING: $HIGH high severity issues found"
    fi
    
    echo "✅ Security gates passed"
```

### Customizable Thresholds

```python
#!/usr/bin/env python3
import json
import sys

CONFIG = {
    'fail_on_critical': True,      # Any critical = fail
    'max_high_issues': 5,           # More than 5 high = fail
    'max_total_issues': 20,         # More than 20 total = fail
}

def check_gates(report):
    stats = report['scan_statistics']
    critical = stats['issues_critical']
    high = stats['issues_high']
    total = stats['total_issues']
    
    failures = []
    
    if CONFIG['fail_on_critical'] and critical > 0:
        failures.append(f"❌ {critical} critical issues found")
    
    if high > CONFIG['max_high_issues']:
        failures.append(f"❌ {high} high issues (max: {CONFIG['max_high_issues']})")
    
    if total > CONFIG['max_total_issues']:
        failures.append(f"❌ {total} total issues (max: {CONFIG['max_total_issues']})")
    
    return failures

# Load and check
with open('repoguard-report.json') as f:
    report = json.load(f)

failures = check_gates(report)

if failures:
    for failure in failures:
        print(failure)
    sys.exit(1)

print("✅ All security gates passed")
```

---

## Branch Protection Rules

### GitHub Branch Protection

1. Go to **Settings** → **Branches**
2. Add rule for `main` or `master`
3. Enable:
   - ✅ **Require status checks to pass** before merging
   - ✅ Select **"Security Scan"** workflow
   - ✅ **Require branches to be up to date**
   - ✅ **Require code reviews**

This prevents:
- Merging without security scan passing
- Merging with critical issues
- Bypassing security checks

### Example Configuration

```yaml
# In repository settings
branch_protection_rules:
  main:
    required_status_checks:
      - security-scan
      - unit-tests
      - code-quality
    require_code_review: 2
    require_branch_protection_updates: true
    require_stale_review_dismissal: false
```

---

## Deployment Pipelines

### Production Deployment Gate

```yaml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install repoguard-cli
      - name: Run Security Scan
        run: repoguard scan --repo . --format json
      - name: Production Gate
        run: |
          CRITICAL=$(jq '.scan_statistics.issues_critical' repoguard-report.json)
          HIGH=$(jq '.scan_statistics.issues_high' repoguard-report.json)
          
          if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 5 ]; then
            echo "❌ DEPLOYMENT BLOCKED"
            echo "Critical: $CRITICAL, High: $HIGH"
            exit 1
          fi
          
          echo "✅ Code approved for production deployment"

  deploy:
    needs: security-check
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to Production
        run: |
          echo "🚀 Deploying to production..."
          # Your deployment steps here
```

### Staging vs Production Gates

```yaml
# Different gates for different environments
jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install repoguard-cli
      - run: repoguard scan --repo . --format json
      - name: Determine Environment
        id: env
        run: |
          if [[ "${{ github.ref }}" == "refs/heads/staging" ]]; then
            echo "environment=staging" >> $GITHUB_OUTPUT
            echo "max_critical=2" >> $GITHUB_OUTPUT
            echo "max_high=10" >> $GITHUB_OUTPUT
          else
            echo "environment=production" >> $GITHUB_OUTPUT
            echo "max_critical=0" >> $GITHUB_OUTPUT
            echo "max_high=3" >> $GITHUB_OUTPUT
          fi
      
      - name: Check Gate
        run: |
          CRITICAL=$(jq '.scan_statistics.issues_critical' repoguard-report.json)
          HIGH=$(jq '.scan_statistics.issues_high' repoguard-report.json)
          
          if [ "$CRITICAL" -gt "${{ steps.env.outputs.max_critical }}" ]; then
            echo "❌ Deployment blocked for ${{ steps.env.outputs.environment }}"
            exit 1
          fi
          
          echo "✅ Gate passed for ${{ steps.env.outputs.environment }}"
```

---

## Emergency Override Process

### Approval Workflow

```yaml
# Emergency fix deployment process
jobs:
  request-override:
    if: failure()
    runs-on: ubuntu-latest
    steps:
      - name: Create Security Review Issue
        uses: actions/github-script@v7
        with:
          script: |
            const issue = await github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: `🔒 Security Override Required: PR #${context.issue.number}`,
              body: `
              ## Security Override Request
              
              This PR has security issues but may need emergency deployment.
              
              - [ ] Security review completed
              - [ ] Risk assessment documented
              - [ ] Approval from security team
              
              @security-team Please review and approve if needed.
              `,
              labels: ['security', 'urgent']
            });
            
            console.log('Created issue:', issue.data.number);
```

### Manual Override

For emergencies only:

```bash
# Override security gate (requires manual approval)
git push --force-with-lease origin main
# Then notify security team immediately
```

**Policy:** Every override must be documented and reviewed within 24 hours.

---

## Monitoring Deployments

### Track What Gets Deployed

```python
#!/usr/bin/env python3
import json
from datetime import datetime

deployment_log = {
    "timestamp": datetime.now().isoformat(),
    "commit": "abc123",
    "security_scan": "passed",
    "critical_issues": 0,
    "high_issues": 2,
    "environment": "production",
    "approved_by": "security-team"
}

with open('deployment_log.json', 'a') as f:
    json.dump(deployment_log, f)
    f.write('\n')
```

### Audit Trail

```yaml
# Keep audit trail of deployments
- name: Log Deployment
  run: |
    cat > deployment.log << EOF
    Date: $(date)
    Commit: ${{ github.sha }}
    Security Status: PASSED
    Issues Found: $(jq '.scan_statistics.total_issues' repoguard-report.json)
    Deployed By: ${{ github.actor }}
    Reason: ${{ github.event.pull_request.title }}
    EOF
    
    git add deployment.log
    git commit -m "Log deployment - ${{ github.sha }}"
    git push
```

---

## Post-Deployment Monitoring

### Security Hotline

```python
# Monitor production for issues that slip through
def production_security_monitor():
    """Alert if issues appear in production"""
    production_scan = scan_production()
    
    for issue in production_scan:
        if issue['severity'] == 'CRITICAL':
            alert_team(f"🚨 CRITICAL issue in production: {issue['type']}")
            create_incident(issue)
```

### Rollback Policy

```yaml
# Automatic rollback on critical issues
- name: Post-Deployment Check
  if: always()
  run: |
    CRITICAL=$(jq '.scan_statistics.issues_critical' repoguard-report.json)
    
    if [ "$CRITICAL" -gt 0 ]; then
      echo "🚨 Critical issues in production!"
      echo "Initiating rollback..."
      git revert HEAD --no-edit
      git push
      echo "Rolled back to previous version"
    fi
```

---

## Metrics & Reports

### Deployment Safety Score

```python
def calculate_safety_score(report):
    """Calculate how safe this deployment is"""
    stats = report['scan_statistics']
    
    score = 100
    score -= stats['issues_critical'] * 10
    score -= stats['issues_high'] * 3
    score -= stats['issues_medium'] * 1
    
    return max(0, score)

# Usage
safety = calculate_safety_score(report)
print(f"Deployment Safety: {safety}/100")

if safety >= 90:
    print("✅ SAFE FOR IMMEDIATE DEPLOYMENT")
elif safety >= 70:
    print("⚠️ DEPLOY WITH CAUTION")
else:
    print("❌ DO NOT DEPLOY")
```

### Security Velocity

```python
def calculate_security_velocity():
    """Track how security improves over time"""
    
    deployment_history = [
        {"date": "2026-01-01", "issues": 50},
        {"date": "2026-01-08", "issues": 35},
        {"date": "2026-01-15", "issues": 20},
    ]
    
    # Calculate trend
    improvement = ((50 - 20) / 50) * 100
    print(f"Security improving: {improvement}% reduction in issues")
```

---

## Best Practices

### Do's ✅
- Always run security scan before deployment
- Document all overrides
- Monitor production after deployment
- Review failed gates with team
- Update gates based on learnings

### Don'ts ❌
- Bypass security gates without approval
- Deploy on Friday afternoon
- Hide security issues in deployment notes
- Skip security reviews for "small" changes
- Assume "it won't happen here"

---

## Compliance Requirements

### SOC2 Compliance
- ✅ Security gates in place
- ✅ Audit trail of deployments
- ✅ Change management process
- ✅ Approval workflows

### ISO27001 Compliance
- ✅ Security assessment before deployment
- ✅ Risk assessment documented
- ✅ Monitoring and logging
- ✅ Incident response procedures

---

## Quick Reference

| Severity | Action |
|----------|--------|
| CRITICAL | ❌ Block deployment, require fix |
| HIGH | ⚠️ Warn, allow review decision |
| MEDIUM | ℹ️ Log, track, plan fix |
| LOW | 📝 Document, fix in next release |

---

## Support

- **Questions?** Check TEAM_INTEGRATION.md
- **Need help?** Create GitHub Issue
- **Emergency?** Contact security@company.com
