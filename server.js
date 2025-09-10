// Import the express library
const express = require('express');

// Initialize the express application
const app = express();
const PORT = 3000;

// --- Hardcoded Secret Key ---
// WARNING: Hardcoding secrets is not recommended for production applications.
// It's better to use environment variables or a secret management service.
const SECRET_API_KEY = 'your-super-secret-key-12345';

// Middleware to check for the secret key in requests
const apiKeyMiddleware = (req, res, next) => {
  const providedApiKey = req.header('x-api-key');

  if (!providedApiKey) {
    return res.status(401).json({ error: 'Unauthorized: API key is missing.' });
  }

  if (providedApiKey !== SECRET_API_KEY) {
    return res.status(403).json({ error: 'Forbidden: Invalid API key.' });
  }

  // If the key is valid, proceed to the next handler
  next();
};

// A public route that doesn't require the API key
app.get('/', (req, res) => {
  res.send('Welcome to the public page!');
});

// A protected route that requires the API key
// We apply our middleware specifically to this route
app.get('/api/protected', apiKeyMiddleware, (req, res) => {
  res.json({
    message: 'Success! You have accessed the protected data.',
    data: [
      { id: 1, item: 'Confidential Info 1' },
      { id: 2, item: 'Confidential Info 2' }
    ]
  });
});

// Start the server and listen on the specified port
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
  console.log('Try accessing the /api/protected route with and without the "x-api-key" header.');
});
