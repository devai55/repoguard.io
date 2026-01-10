# Sample test file with security issues

# This should trigger a warning
DATABASE_PASSWORD = "super_secret_123"

# This should also trigger
API_KEY = "sk-1234567890abcdef"

# TODO: security - fix this authentication issue

def connect():
    pass
