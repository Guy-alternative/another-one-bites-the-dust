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
