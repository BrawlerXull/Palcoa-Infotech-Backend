const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());


const corsOptions = {
  origin: 'http://localhost:5173',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  credentials: true,
};
app.use(cors(corsOptions));


function generateRandomString(length) {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(length, (err, buffer) => {
      if (err) {
        reject(err);
      } else {
        resolve(buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
      }
    });
  });
}


app.get('/', (req, res) => {
  res.json({ message: 'hello' });
});


app.post('/auth', async (req, res) => {
  const { email, password } = req.body;

  if (email === 'admin' && password === 'admin') {
    try {
      const randomToken = await generateRandomString(32);
      const expirationTime = new Date(Date.now() + 5 * 60 * 1000);

      res.cookie('token', randomToken, {
        expires: expirationTime,
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
      });

      res.status(200).json({ message: 'Signed in successfully' });
    } catch (err) {
      res.status(500).json({ error: 'Failed to generate token' });
    }
  } else {
    res.status(401).json({ error: 'Authentication failed' });
  }
});


app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});