// Dangerous JavaScript patterns

// Insecure Random
const token = Math.random();

// Hardcoded Admin
const username = "admin";
const isAdmin = true;

// Dangerous Eval
const result = eval(userInput);
exec(userCode);

// Command Injection (Node.js)
const { exec } = require('child_process');
exec('ls ' + userDir);

// Path Traversal
const fs = require('fs');
fs.readFileSync(userPath + '/../../etc/passwd');