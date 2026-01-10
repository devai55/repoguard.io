# Contributing to RepoGuard

Thank you for your interest in contributing to RepoGuard! We welcome contributions from the community.

## 🚀 Quick Start

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/repoguard.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `python -m pytest`
6. Commit your changes: `git commit -am 'Add some feature'`
7. Push to the branch: `git push origin feature/your-feature-name`
8. Submit a pull request

## 🛠️ Development Setup

```bash
# Install development dependencies
pip install -r requirements.txt

# Run the scanner
python repoguard.py scan --repo .

# Run tests
python -m pytest

# Format code
black repoguard.py

# Lint code
flake8 repoguard.py
```

## 📋 Development Guidelines

### Code Style
- Follow PEP 8 style guidelines
- Use `black` for code formatting
- Use descriptive variable and function names
- Add docstrings to all functions and classes

### Testing
- Write tests for new features
- Ensure all tests pass before submitting PR
- Test both positive and negative cases

### Security
- Never commit secrets or sensitive data
- Use secure coding practices
- Report security issues privately to security@repoguard.dev

## 🐛 Reporting Bugs

When reporting bugs, please include:
- RepoGuard version
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs

## 💡 Feature Requests

We love feature ideas! Please:
- Check if the feature already exists
- Search existing issues for similar requests
- Provide detailed use cases
- Explain the benefit to users

## 📝 Commit Messages

Use clear, descriptive commit messages:
- `feat: add support for custom security rules`
- `fix: resolve issue with license validation`
- `docs: update installation instructions`
- `test: add unit tests for secret detection`

## 🔒 Security Policy

See our [Security Policy](SECURITY.md) for information about reporting security vulnerabilities.

## 📞 Support

- **Documentation**: [docs.repoguard.dev](https://docs.repoguard.dev)
- **Discussions**: [GitHub Discussions](https://github.com/repoguard/repoguard/discussions)
- **Issues**: [GitHub Issues](https://github.com/repoguard/repoguard/issues)

## 📄 License

By contributing to RepoGuard, you agree that your contributions will be licensed under the MIT License.