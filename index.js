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

mongoose.connect('mongodb://localhost:27017/key')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

const keySchema = new mongoose.Schema({
  publicKey: { type: String, required: true },
  privateKey: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
});

const Key = mongoose.model('Key', keySchema);

const decryptedProductSchema = new mongoose.Schema({
  productName: { type: String, required: true },
  price: { type: String, required: true },
  description: { type: String, required: true },
  category: { type: String, required: true },
  stock: { type: String, required: true },
  publicKey: { type: String, required: true },
  failed: { type: Boolean, default: false },
  originalId: { type: Number, required: true },
});

const DecryptedProduct = mongoose.model('DecryptedProduct', decryptedProductSchema);

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

app.post('/send', async (req, res) => {
  const { data } = req.body;
  console.log("Request received");

  try {
    for (const product of data) {
      let { public_key, ...encryptedFields } = product;
      console.log(public_key)

      const privateKey = await getPrivateKeyFromPublicKey(public_key);
      if (!privateKey) {

        console.log("hess")
        return res.status(400).json({ message: 'Private key not found for the provided public key', success: false });
      }
      
      console.log("hess")

      console.log("Encrypted fields:", encryptedFields);
      
      try {
        const decryptedProduct = decryptProduct(encryptedFields, privateKey);
        console.log("Decrypted product:", decryptedProduct);

        const decryptedProductDoc = new DecryptedProduct({
          productName: encryptedFields.productName,
          price: decryptedProduct.price,
          description: encryptedFields.description,
          category: decryptedProduct.category,
          stock: decryptedProduct.stock,
          publicKey: public_key,
          originalId: product.id,
        });

        await decryptedProductDoc.save();
      } catch (err) {
        console.log("Error while decrypting product:", err);
        return res.status(500).json({ message: 'Error while decrypting product', success: false, error: err.message });
      }
    }

    return res.status(201).json({ message: 'Decrypted data stored successfully', success: true });
  } catch (err) {
    console.log("Error while processing request:", err);
    return res.status(500).json({ message: 'Failed to store decrypted data', success: false, error: err.message });
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

function decryptProduct(encryptedFields, privateKey) {
  const decryptedFields = {};

  try {
    for (const [key, encryptedValue] of Object.entries(encryptedFields)) {
      if (key === 'failed' || key === 'id' || key == 'productName' || key == 'description') continue;
      console.log(`Decrypting ${key}: ${encryptedValue}`);
      const buffer = Buffer.from(encryptedValue, 'base64');
      const decrypted = crypto.privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_NO_PADDING,
        },
        buffer
      );
      decryptedFields[key] = decrypted.toString('utf-8');
    }
  } catch (err) {
    console.log("Error while decrypting product:", err);
    throw err;  // Re-throw the error after logging it
  }

  return decryptedFields;
}

async function getPrivateKeyFromPublicKey(publicKey) {
  const keyDocument = await Key.findOne({ publicKey: publicKey });
  console.log("Key Document : " , keyDocument);
  return keyDocument ? keyDocument.privateKey : null;
}

app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});
