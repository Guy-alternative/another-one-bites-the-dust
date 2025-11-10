// bad-practice.js
// Example of exposed AWS credentials (FAKE KEYS - DO NOT USE)

// Hardcoded AWS credentials (this is a vulnerability!)
const AWS_ACCESS_KEY_ID = "AKIAFAKEACCESSKEY1234";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKESECRETKEY123";

// Example usage (not functional, for testing AppSec scanners only)
function connectToAWS() {
    console.log("Connecting to AWS with Access Key:", AWS_ACCESS_KEY_ID);
    // ... would normally initialize AWS SDK here
}

connectToAWS();

// FAKE DB Password (common pattern)
// Scanners look for keys like 'password', 'secret', etc., with a string value.
const DB_PASSWORD = "myS3curePassword123!";

// --- 2. SAST-Detectable Vulnerability: Command Injection ---
// SAST tools analyze code without executing it (statically) to find
// vulnerabilities. One of the most common is "injection".

const { exec } = require('child_process');

/**
 * Simulates a function (like an Express.js route handler)
 * that takes user input and uses it in an unsafe way.
 * * @param {object} req - Simulated request object (e.g., from Express)
 * @param {object} res - Simulated response object
 */
function getUserFile(req, res) {
  // 'req.query.filename' comes from an external user (e.g., a URL parameter).
  // It is "tainted" or untrusted.
  const userInput = req.query.filename;

  // VULNERABILITY: Command Injection
  // This line directly concatenates the untrusted 'userInput' into a
  // shell command.
  // A SAST tool will detect this data flow:
  // 1. Source: User input from `req.query.filename`
  // 2. Sink: A dangerous function like `exec()`
  //
  // An attacker could provide input like: "userfile.txt; rm -rf /"
  // The final command would be: "cat /var/user_files/userfile.txt; rm -rf /"
  exec('cat /var/user_files/' + userInput, (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return res.send('Error');
    }
    res.send(`File content: ${stdout}`);
  });
}

// --- 3. SAST-Detectable Vulnerability: SQL Injection (SQLi) ---

/**
 * Simulates a database query function.
 * @param {object} dbClient - Simulated database client
 * @param {object} req - Simulated request object
 */
function getUserDetails(dbClient, req) {
  // 'req.query.userId' is untrusted user input.
  const userId = req.query.userId;

  // VULNERABILITY: SQL Injection
  // The 'userId' is directly concatenated into the SQL query string.
  // A SAST tool will detect this data flow:
  // 1. Source: User input from `req.query.userId`
  // 2. Sink: A database query function (e.g., `dbClient.query`)
  //
  // An attacker could provide input like: "123 OR 1=1"
  // The final query would be: "SELECT * FROM users WHERE id = 123 OR 1=1"
  // This would return all users in the table.
  const query = "SELECT * FROM users WHERE id = " + userId;
  
  dbClient.query(query, (err, results) => {
    if (err) {
      console.error('DB error:', err);
      return;
    }
    console.log('User data:', results);
  });
}

// --- 4. SAST-Detectable Vulnerability: Cross-Site Scripting (XSS) ---

/**
 * Simulates rendering a user's name on a page.
 * @param {object} res - Simulated response object
 * @param {object} req - Simulated request object
 */
function renderUserProfile(req, res) {
  // 'req.query.username' is untrusted user input.
  const username = req.query.username;

  // VULNERABILITY: Reflected Cross-Site Scripting (XSS)
  // The 'username' is directly included in the HTML response.
  // A SAST tool will detect this data flow:
  // 1. Source: User input from `req.query.username`
  // 2. Sink: An HTML response sink (e.g., `res.send`, `res.write`)
  //
  // An attacker could provide input like: "<script>alert('XSS')</script>"
  // The HTML response would be: "<h1>Welcome, <script>alert('XSS')</script></h1>"
  // This would execute the script in the victim's browser.
  res.send(`<h1>Welcome, ${username}</h1>`);
}

// --- 5. SAST-Detectable Vulnerability: Insecure Randomness ---

/**
 * Simulates generating a "secure" token.
 */
function generateResetToken() {
  // VULNERABILITY: Use of a weak pseudorandom number generator (PRNG).
  // SAST tools will flag 'Math.random()' when used in a security-sensitive
  // context (like generating tokens, passwords, or session IDs).
  // These numbers are predictable.
  //
  // The correct method is to use `crypto.randomBytes()`.
  const token = Math.random().toString(36).substring(2);
  return token;
}


// Example of how this might be called (for context)
const simulated_request = {
  query: {
    filename: "test.txt" // This is the user-controlled input
  }
};

const simulated_response = {
  send: (data) => console.log(data)
};
