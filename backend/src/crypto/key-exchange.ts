import * as crypto from 'crypto';

// RSA-OAEP Key Pair for E2EE Key Exchange (Hybrid Encryption)
// Generates a 2048-bit key pair upon server initialization
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

export const E2EEServerKeys = {
    publicKey,
    // Unwraps the AES key sent by the client
    decryptAESKey(encryptedKeyBase64: string): Buffer {
        const encryptedKeyBuffer = Buffer.from(encryptedKeyBase64, 'base64');
        return crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            encryptedKeyBuffer
        );
    }
};
