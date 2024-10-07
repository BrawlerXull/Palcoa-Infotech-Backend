const crypto = require('crypto');
const fs = require('fs');

// Read the public key
const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2q+roCCT0AcN9erx8F+2
rTgXqLEGlXg3wgfTp6H7RYe4aQalFH4Xu64F/Nty2vclXGQyoAEcsjwJ3HS64I7u
4AWnOnZuBr7L4UhzpA+3Q4I32LSoHahX94tn3ZH0N0XDVD5gR9Y+Z42EUIHFOom2
bleoOqPpBHLyHIJeRRqfK3rkyYdDssjJsU+7y/ZfhxVzPFtlv84N+4sssQRIXmBU
VYUz0t/JwRn8aWkTRS6BTHktLRtvCj6eHuSovWzRCNsEPXWMqB9aTXpBChskeKX/
U139G0VekgIJl+/3XS3ZBF0RrR+aRfOmQ2TG+kaAkxJN26Brht0Hm/VYHkFp2kp/
7wIDAQAB
-----END PUBLIC KEY-----`;

// Encrypt some data
const data = 'dbfjdbfljadsbnfljdsbfljndslkfnsdakfnsdlkfnewkfnl;wkfnlekrnflerfn';
const buffer = Buffer.from(data, 'utf8');
const encrypted = crypto.publicEncrypt(
  {
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  },
  buffer
);

const encryptedData = encrypted.toString('base64');
console.log('Encrypted data:', encryptedData);
