# Test file for RepoGuard CI/CD workflow
# This file contains intentional security issues to test the automated scanning

import os

# Intentional security issue - hardcoded password
DATABASE_PASSWORD = "super_secret_password_123"

# Intentional security issue - API key in code
API_KEY = "sk-test1234567890abcdef"

# Intentional security issue - private key
PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
-----END PRIVATE KEY-----"""

def connect_to_database():
    # This would be flagged as insecure database connection
    return f"postgresql://user:{DATABASE_PASSWORD}@localhost/db"

def make_api_call():
    # This would be flagged as API key exposure
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return headers

if __name__ == "__main__":
    print("This is a test file with intentional security vulnerabilities")
    print("RepoGuard should detect these issues in the CI/CD pipeline")