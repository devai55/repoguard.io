# Security Metrics & Monitoring Guide

## Overview

Track your codebase's security health over time with RepoGuard metrics and monitoring.

---

## Key Metrics to Monitor

### 1. Security Risk Score

**What it measures:** Overall code security health (0-100)

**How to track:**
```bash
repoguard scan --repo . --format json | jq '.scan_statistics.risk_score'
```

**What's healthy:**
- 0-50: Low risk ✅
- 51-75: Medium risk ⚠️
- 76-100: High risk 🔴

**Track over time:**
```bash
# Store in CSV
echo "$(date),$(repoguard scan ... | jq '.risk_score')" >> risk-history.csv
```

### 2. Issue Trends

**Track by severity:**
- Critical issues found
- High severity issues found
- Medium/Low issues found

**Example dashboard query:**
```sql
SELECT date, critical, high, medium
FROM security_scans
ORDER BY date DESC
LIMIT 30
```

### 3. Time to Resolution

**What it measures:** How quickly security issues are fixed

**Healthy target:**
- Critical: < 24 hours
- High: < 7 days
- Medium: < 30 days

**Track per issue:**
```json
{
  "issue_id": "sec-123",
  "severity": "CRITICAL",
  "found_date": "2026-01-12",
  "fixed_date": "2026-01-13",
  "days_to_fix": 1
}
```

---

## Monitoring Dashboard

### GitHub Actions Insights

1. Go to **Actions** tab in your repository
2. Click **Security Scan** workflow
3. View:
   - Success/failure rate
   - Average scan time
   - Trend over time

### Create Custom Dashboard

#### Option 1: GitHub Wiki

Create `wiki/Security-Metrics.md`:

```markdown
# Monthly Security Report

| Month | Critical | High | Total | Status |
|-------|----------|------|-------|--------|
| Jan 2026 | 18 | 32 | 60 | 🔴 HIGH |
| Feb 2026 | 8 | 18 | 26 | 🟡 MEDIUM |
| Mar 2026 | 2 | 5 | 7 | 🟢 LOW |

**Trend:** Issues decreased 88% in 2 months ✅
```

#### Option 2: Automated Reports

```python
#!/usr/bin/env python3
import json
import subprocess
from datetime import datetime

# Run scan
result = subprocess.run(
    ['repoguard', 'scan', '--repo', '.', '--format', 'json'],
    capture_output=True,
    text=True
)

# Parse results
report = json.loads(result.stdout)
stats = report['scan_statistics']

# Generate markdown
markdown = f"""
# Security Scan Report - {datetime.now().date()}

## Summary
- **Risk Level:** {stats['risk_level']}
- **Total Issues:** {stats['total_issues']}
- **Critical:** {stats['issues_critical']}
- **High:** {stats['issues_high']}
- **Medium:** {stats['issues_medium']}

## Trend Analysis
Issues detected: {stats['total_issues']}
Files scanned: {stats['files_scanned']}
Lines analyzed: {stats['lines_analyzed']}
"""

# Save report
with open('SECURITY_REPORT.md', 'w') as f:
    f.write(markdown)

print("✅ Report generated: SECURITY_REPORT.md")
```

---

## Alerting & Notifications

### Alert Conditions

```yaml
# Alert when:
- critical_issues > 0          # Any critical issues
- high_issues_trend > 10%      # High issues increasing
- avg_resolution_time > 7 days # Taking too long to fix
- risk_score > 75              # Overall risk is high
```

### Email Alerts

```python
import smtplib
from email.mime.text import MIMEText

def send_alert(severity, message):
    msg = MIMEText(f"🚨 Security Alert\n{message}")
    msg['Subject'] = f"Security Alert: {severity}"
    msg['From'] = "security@company.com"
    msg['To'] = "team@company.com"
    
    server = smtplib.SMTP('localhost')
    server.send_message(msg)
    server.quit()

# Usage
send_alert("CRITICAL", "18 critical issues detected in PR #123")
```

### Slack Notifications

```yaml
- name: Slack Alert on Critical Issues
  if: steps.scan.outputs.critical > 0
  uses: slackapi/slack-github-action@v1
  with:
    webhook-url: ${{ secrets.SLACK_WEBHOOK }}
    payload: |
      {
        "text": "🚨 Critical Security Issues",
        "blocks": [
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "*Repository:* ${{ github.repository }}\n*Critical Issues:* ${{ steps.scan.outputs.critical }}"
            }
          }
        ]
      }
```

---

## Metrics by Team

### Track Security by Developer

```python
def analyze_by_author():
    """Track which developers introduce most security issues"""
    for commit in git_log():
        issues = repoguard_scan(commit)
        print(f"{commit.author}: {len(issues)} issues")
```

### Track Security by Module

```python
def analyze_by_module():
    """Identify high-risk modules"""
    modules = {}
    for issue in scan_results:
        module = issue['file'].split('/')[0]
        modules[module] = modules.get(module, 0) + 1
    
    return sorted(modules.items(), key=lambda x: x[1], reverse=True)
```

Output:
```
auth/           12 issues
payment/        8 issues
api/            5 issues
utils/          3 issues
```

---

## Compliance Reporting

### Generate Monthly Report

```yaml
name: Monthly Compliance Report

on:
  schedule:
    - cron: '0 9 1 * *'  # First day of month

jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install repoguard-cli
      - name: Run Scan
        run: repoguard scan --repo . --format json > report.json
      - name: Generate Report
        run: |
          python3 << 'EOF'
          import json
          from datetime import datetime
          
          with open('report.json') as f:
              data = json.load(f)
          
          report = f"""
          # Monthly Compliance Report
          Date: {datetime.now().date()}
          
          ## Executive Summary
          - Total Issues: {data['scan_statistics']['total_issues']}
          - Critical Issues: {data['scan_statistics']['issues_critical']}
          - Compliance Status: {'✅ PASS' if data['scan_statistics']['issues_critical'] == 0 else '❌ FAIL'}
          
          ## Remediation Status
          - Issues Fixed This Month: [Count from tracking]
          - Average Resolution Time: [Calculate from data]
          - Outstanding Issues: {data['scan_statistics']['total_issues']}
          """
          
          with open('compliance_report.pdf', 'w') as f:
              f.write(report)
          EOF
      - uses: actions/upload-artifact@v4
        with:
          name: compliance-report-${{ github.run_id }}
          path: compliance_report.pdf
```

---

## Setting Goals

### Example Security Goals

**Q1 2026:**
- Reduce critical issues to < 5
- Fix 80% of high severity issues
- Implement security training for team
- Establish security review process

**Q2 2026:**
- Zero critical issues
- Average resolution time < 24 hours
- Integrate security into definition of done
- Monthly security reports

**Q3 2026:**
- Security metrics in CI/CD gates
- Automated security in all repos
- Team certification on secure coding
- Industry compliance (SOC2, ISO27001)

---

## Tools Integration

### Integrate with Existing Tools

#### Jira Integration
```python
from jira import JIRA

jira = JIRA('https://company.atlassian.net')

for issue in scan_results:
    jira.create_issue(
        project='SEC',
        issuetype='Bug',
        summary=f"Security: {issue['type']}",
        description=issue['recommendation'],
        priority='Highest' if issue['severity'] == 'CRITICAL' else 'High'
    )
```

#### Datadog Integration
```python
from datadog import api

api.Metric.send(
    metric='security.issues.critical',
    points=scan_results['critical_count'],
    tags=['team:security', 'env:prod']
)
```

#### CloudWatch Integration
```python
import boto3

cloudwatch = boto3.client('cloudwatch')
cloudwatch.put_metric_data(
    Namespace='RepoGuard',
    MetricData=[
        {
            'MetricName': 'CriticalIssues',
            'Value': scan_results['critical_count']
        }
    ]
)
```

---

## Visualization Examples

### Risk Score Over Time

```
100 |                    ▁
 75 | ▇▇▇▇▇▇▇▇▇▇▇▇▇     ▂
 50 | ░░░░░░░░░░░░░▁▁▁▂
 25 |                     ▃
  0 |_____________________▄____
    Jan Feb Mar Apr May Jun Jul
```

### Issues by Severity

```
Critical: ████████████████ 18
High:     ███████████████████████████████ 32
Medium:   █████ 5
Low:      ░ 0
Info:     ░░░ 3
```

### Time to Resolution

```
Average: 4.2 days
- Critical: 1.1 days ✅
- High: 5.3 days ⚠️
- Medium: 12.4 days ⚠️
```

---

## Best Practices

1. **Review metrics weekly** - Catch trends early
2. **Share with leadership** - Show security ROI
3. **Set improvement goals** - Make security measurable
4. **Celebrate wins** - When metrics improve, acknowledge the team
5. **Use data-driven decisions** - Base security investment on metrics
