# Dangerous code patterns for testing

# SQL Injection
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
db.execute(f"SELECT * FROM users WHERE name = '{name}'")

# Command Injection
os.system("ls " + directory)
subprocess.call("grep " + pattern + " file.txt")

# Path Traversal
with open(user_input + "/../../etc/passwd") as f:
    data = f.read()

# Dangerous Eval
result = eval(user_input)
exec(code_from_user)

# Insecure Random
token = random.random()
session_id = Math.random()

# Hardcoded Admin
username = "admin"
user = 'admin'
is_admin = True