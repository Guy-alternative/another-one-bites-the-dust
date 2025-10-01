/**
 * app.js
 * Intentional SCA + SAST test file:
 * - Uses vulnerable package versions (see package.json)
 * - Contains multiple insecure code patterns SAST engines should flag
 *
 * Vulnerabilities to be detected by SAST:
 *  - SQL injection via string concatenation
 *  - Command injection via child_process.exec with unescaped input
 *  - Unsafe deserialization / use of eval on untrusted input
 *  - Disabling TLS certificate validation
 *  - Use of deprecated/insecure packages (SCA should flag by package.json)
 */

const _ = require('lodash');           // vulnerable version from package.json
const request = require('request');    // deprecated package; SCA should flag
const mysql = require('mysql');        // used insecurely below
const serialize = require('serialize-javascript'); // old version in package.json
const { exec } = require('child_process');
const http = require('http');

// ----------------------------
// Insecure: disabling TLS verification (SAST should flag this).
// ----------------------------
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // NEVER do this in real code

// ----------------------------
// SCA: prototype pollution risk (lodash < 4.17.21). Using _.merge on user data.
// SAST: use of untrusted user input without validation.
// ----------------------------
function mergeUserConfig(userInput) {
  // Suppose userInput comes from an external source; merging without validation
  const defaultConfig = { retries: 3, timeout: 5000, features: { beta: false } };
  return _.merge({}, defaultConfig, userInput);
}

// ----------------------------
// SAST: SQL injection (unsafe string concatenation).
// ----------------------------
function getUserByIdUnsafe(dbConn, userId, callback) {
  // UNSAFE: userId is inserted directly into SQL string
  const query = "SELECT id, username, email FROM users WHERE id = " + userId + ";";
  dbConn.query(query, (err, results) => {
    callback(err, results);
  });
}

// ----------------------------
// SAST: command injection via child_process.exec with untrusted input
// ----------------------------
function runDiagnostics(userProvidedArg) {
  // UNSAFE: if userProvidedArg contains shell metacharacters, this is command injection
  const cmd = `echo "diag start"; ls ${userProvidedArg}; echo "diag end"`;
  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      console.error("Diagnostics failed:", err);
      return;
    }
    console.log(stdout);
  });
}

// ----------------------------
// SAST: unsafe deserialization using eval/serialize-javascript (older versions may be vulnerable)
// ----------------------------
function unsafeDeserialize(serialized) {
  // Old unsafe pattern: using eval or untrusted "serialize-javascript" outputs
  // Here we demonstrate eval of untrusted input (intentionally bad).
  try {
    // eslint-disable-next-line no-eval
    const obj = eval("(" + serialized + ")");
    return obj;
  } catch (e) {
    console.error("Deserialization failed", e);
    return null;
  }
}

// ----------------------------
// Minimal demo server to show how untrusted data might flow in (for scanner coverage)
// ----------------------------
const pool = mysql.createPool({
  host: "127.0.0.1",
  user: "test",
  password: "test",
  database: "testdb",
  connectionLimit: 2
});

http.createServer((req, res) => {
  const url = require('url').parse(req.url, true);
  const q = url.query;

  // Example SCA detection: `request` usage (deprecated)
  // SAST: unsafe use of query.payload via eval
  if (url.pathname === '/submit' && q.payload) {
    const deserialized = unsafeDeserialize(q.payload); // should be flagged
    // merge without validation -> prototype pollution risk
    const merged = mergeUserConfig(deserialized);

    // Unsafe SQL call: q.id used directly
    getUserByIdUnsafe(pool, q.id, (err, user) => {
      if (err) {
        res.writeHead(500); res.end("db error");
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ merged, user }));
    });
    return;
  }

  // Demo endpoint that triggers child_process.exec with user arg
  if (url.pathname === '/diag' && q.dir) {
    runDiagnostics(q.dir); // should be flagged for command injection
    res.writeHead(200); res.end("diagnostics started");
    return;
  }

  // Example of making an outbound HTTP request with deprecated `request`
  if (url.pathname === '/proxy' && q.target) {
    // SCA should flag `request` itself; this demonstrates usage.
    request(q.target, { timeout: 2000 }, (err, response, body) => {
      if (err) {
        res.writeHead(502); res.end("upstream error");
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(body.slice(0, 100));
    });
    return;
  }

  res.writeHead(200);
  res.end("OK");
}).listen(3000, () => {
  console.log("Test server listening on http://localhost:3000");
});

// ----------------------------
// Example usage of serialize-javascript (older versions flagged by SCA)
// ----------------------------
const insecureSerialized = serialize({ a: 1, b: 2 }); // older versions could be flagged
console.log("insecureSerialized length:", insecureSerialized.length);

// Export functions so SAST scanners that check code paths see usage
module.exports = {
  mergeUserConfig,
  getUserByIdUnsafe,
  runDiagnostics,
  unsafeDeserialize
};
