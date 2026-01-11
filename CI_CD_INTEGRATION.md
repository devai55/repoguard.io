# RepoGuard CI/CD Integration Examples

## GitHub Actions (Recommended)

The `.github/workflows/security-scan.yml` provides a complete security scanning pipeline that:

- **Triggers on**: Push, PR, weekly schedule, manual dispatch
- **Scans**: Code for secrets, vulnerabilities, and security issues
- **Reports**: JSON artifacts, PR comments, build failures on critical issues
- **Integrates**: With GitHub's security features

### Key Features:

1. **Comprehensive Scanning**: Full codebase analysis with historical git scanning
2. **Risk-Based Actions**: Fails builds on critical issues, warns on high severity
3. **PR Integration**: Automatic comments with scan results and links to reports
4. **Artifact Storage**: Detailed JSON reports saved for 30 days
5. **Scheduled Scans**: Weekly automated security audits

## Other CI/CD Platforms

### GitLab CI/CD

```yaml
stages:
  - security

security_scan:
  stage: security
  image: python:3.8
  before_script:
    - pip install repoguard-cli
  script:
    - repoguard scan --repo . --format json
  artifacts:
    reports:
      junit: repoguard-report.json
    expire_in: 1 week
  only:
    - merge_requests
    - main
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install repoguard-cli'
                sh 'repoguard scan --repo . --format json'

                script {
                    def report = readJSON file: 'repoguard-report.json'
                    def critical = report.scan_statistics.issues_critical
                    def high = report.scan_statistics.issues_high

                    if (critical > 0) {
                        error("🚨 Critical security issues found: ${critical}")
                    } else if (high > 0) {
                        echo "⚠️ High severity issues detected: ${high}"
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'repoguard-report.json', fingerprint: true
        }
    }
}
```

### Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.8'

- script: |
    pip install repoguard-cli
    repoguard scan --repo . --format json
  displayName: 'Run RepoGuard Security Scan'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: 'repoguard-report.json'
    artifactName: 'SecurityReport'
  condition: always()
```

## Local Development Integration

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: repoguard
        name: RepoGuard Security Scan
        entry: repoguard scan --repo . --format text
        language: system
        pass_filenames: false
        files: \.(py|js|ts|java|go|rs)$
```

### VS Code Task

Add to `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Security Scan",
      "type": "shell",
      "command": "repoguard",
      "args": ["scan", "--repo", ".", "--format", "text"],
      "group": "build",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": false,
        "panel": "shared"
      }
    }
  ]
}
```

## Integration Benefits

### 🔒 **Security Gates**
- Prevent deployment of insecure code
- Enforce security standards across teams
- Catch issues before they reach production

### 📊 **Compliance & Auditing**
- Automated compliance reporting
- Audit trails of security scans
- Evidence for security certifications

### 🚀 **Developer Experience**
- Fast feedback during development
- Clear remediation guidance
- Integrated into existing workflows

### 📈 **Metrics & Insights**
- Security trend analysis
- Team performance tracking
- Risk assessment over time

## Configuration Options

### Environment Variables
```bash
# Set RepoGuard license key
export REPOGUARD_LICENSE_KEY="your-license-key"

# Configure scan behavior
export REPOGUARD_CONFIG_PATH="./repoguard-config.json"
```

### Custom Configuration
Create `repoguard-config.json`:
```json
{
  "exclude_patterns": ["test/**", "*.min.js"],
  "severity_threshold": "high",
  "enable_git_history_scan": true,
  "custom_rules": []
}
```

This integration transforms security from a manual, afterthought process into an automated, proactive part of your development lifecycle!