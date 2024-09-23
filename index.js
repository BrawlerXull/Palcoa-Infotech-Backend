const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');

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


mongoose.connect('mongodb://localhost:27017/key', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));


const keySchema = new mongoose.Schema({
  publicKey: { type: String, required: true },
  privateKey: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
});

const Key = mongoose.model('Key', keySchema);


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


app.get('/form', async (req, res) => {
  try {
    const lastKey = await Key.findOne().sort({ _id: -1 });

    if (lastKey && !lastKey.isVerified) {

      return res.status(200).json({ message: 'Returning last key', public_key: lastKey.publicKey, success: true });
    } else {

      const { publicKey, privateKey } = generateKeyPair();

      const keyDocument = new Key({ publicKey, privateKey, isVerified: false });
      await keyDocument.save();

      res.status(200).json({ message: 'Keys generated successfully', public_key: publicKey, success: true });
    }
  } catch (err) {
    res.status(500).json({ message: 'Failed to generate keys', success: false });
  }
});


function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}


app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});
