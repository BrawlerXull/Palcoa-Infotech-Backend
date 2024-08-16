const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const cookieParser = require('cookie-parser'); 

const app = express();
app.use(express.json());
app.use(cookieParser()); 

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

      res.cookie('token', randomToken, {
        httpOnly: true, 
        secure: false, 
        sameSite: 'Lax',
      });

      res.status(200).json({ message: 'Signed in successfully', success: true });
    } catch (err) {
      res.status(500).json({ message: 'Failed to generate token', success: false });
    }
  } else {
    res.status(401).json({ message: 'Authentication failed', success: false });
  }
});


app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});
