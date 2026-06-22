/**
 * OmniID GDPR — TLS Configuration Module
 * 
 * Configures HTTPS server with TLS 1.3 enforcement, restricted cipher suites,
 * and optional mTLS (mutual TLS) for high-security issuance endpoints.
 * 
 * GDPR Articles: Art. 5(1)(f), Art. 32 — Data in transit protection
 */

import * as https from 'https';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Express } from 'express';

export interface TLSOptions {
    certPath?: string;
    keyPath?: string;
    caPath?: string;         // CA for mTLS client certificate validation
    enableMTLS?: boolean;
    port?: number;
}

/**
 * Allowed cipher suites in priority order (TLS 1.3 only)
 */
const ALLOWED_CIPHERS = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256'
].join(':');

/**
 * Generate a self-signed certificate for development environments.
 * In production, use Let's Encrypt or a proper CA.
 */
function generateDevCertificate(certDir: string): { certPath: string; keyPath: string } {
    const certPath = path.join(certDir, 'dev-cert.pem');
    const keyPath = path.join(certDir, 'dev-key.pem');

    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
        console.log('[TLS] Using existing development certificates.');
        return { certPath, keyPath };
    }

    console.log('[TLS] Generating self-signed development certificate...');

    // Generate RSA key pair (4096 bits for dev)
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // Create self-signed certificate using Node.js crypto
    // Note: For a real self-signed cert, you'd use openssl or a library like node-forge.
    // This simplified version writes the keys; a proper X.509 cert requires ASN.1 encoding.
    // In production, use `openssl req -x509 -newkey rsa:4096 -nodes ...`
    
    if (!fs.existsSync(certDir)) {
        fs.mkdirSync(certDir, { recursive: true });
    }

    // Write a placeholder self-signed cert instruction
    const certInstructions = [
        '# Development Certificate',
        '# Run the following command to generate a proper self-signed certificate:',
        `# openssl req -x509 -newkey rsa:4096 -keyout ${keyPath} -out ${certPath} -days 365 -nodes -subj "/CN=localhost"`,
        '',
        '# For production, use Let\'s Encrypt:',
        '# certbot certonly --standalone -d yourdomain.com'
    ].join('\n');

    // Write the private key for dev usage
    fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });
    fs.writeFileSync(certPath, publicKey); // Placeholder - needs proper X.509 cert

    console.log('[TLS] Development key pair generated. Run OpenSSL command for proper X.509 certificate.');
    console.log(`[TLS] Key: ${keyPath}`);

    return { certPath, keyPath };
}

/**
 * Create an HTTPS server with hardened TLS configuration.
 */
export function createSecureServer(app: Express, options: TLSOptions = {}): https.Server {
    const port = options.port || parseInt(process.env.HTTPS_PORT || '3443');
    const certDir = path.join(__dirname, '..', '..', 'certs');

    let certPath = options.certPath || process.env.TLS_CERT_PATH;
    let keyPath = options.keyPath || process.env.TLS_KEY_PATH;
    const caPath = options.caPath || process.env.TLS_CA_PATH;

    // Auto-generate dev certs if none provided
    if (!certPath || !keyPath || !fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
        console.log('[TLS] No certificates found. Generating development certificates...');
        const devCerts = generateDevCertificate(certDir);
        certPath = devCerts.certPath;
        keyPath = devCerts.keyPath;
    }

    const tlsOptions: https.ServerOptions = {
        // Certificate chain
        cert: fs.readFileSync(certPath),
        key: fs.readFileSync(keyPath),

        // TLS version enforcement — TLS 1.3 only
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',

        // Cipher suite restriction
        ciphers: ALLOWED_CIPHERS,

        // Disable session resumption tickets for forward secrecy
        // (TLS 1.3 handles this natively with 0-RTT protections)

        // ECDH curve preference
        ecdhCurve: 'X25519:P-256:P-384',

        // Honor server cipher order
        honorCipherOrder: true,
    };

    // Enable mTLS if configured
    if (options.enableMTLS || process.env.ENABLE_MTLS === 'true') {
        if (caPath && fs.existsSync(caPath)) {
            tlsOptions.ca = fs.readFileSync(caPath);
            tlsOptions.requestCert = true;
            tlsOptions.rejectUnauthorized = true;
            console.log('[TLS] Mutual TLS (mTLS) enabled for client certificate authentication.');
        } else {
            console.warn('[TLS] mTLS requested but CA certificate not found. Falling back to standard TLS.');
        }
    }

    const server = https.createServer(tlsOptions, app);

    server.listen(port, () => {
        console.log(`[TLS] Secure HTTPS server listening on port ${port}`);
        console.log(`[TLS] Protocol: TLS 1.3 only`);
        console.log(`[TLS] Ciphers: ${ALLOWED_CIPHERS}`);
        console.log(`[TLS] mTLS: ${tlsOptions.requestCert ? 'ENABLED' : 'DISABLED'}`);
    });

    return server;
}

/**
 * Middleware to enforce HTTPS redirect on HTTP connections.
 * Place this on the HTTP server (port 80) to redirect all traffic.
 */
export function httpsRedirectMiddleware(httpsPort: number = 443) {
    return (req: any, res: any, next: any) => {
        if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
            return next();
        }
        const host = req.headers.host?.replace(/:\d+$/, '') || 'localhost';
        const redirectUrl = `https://${host}:${httpsPort}${req.url}`;
        res.redirect(301, redirectUrl);
    };
}

/**
 * mTLS verification middleware for protected endpoints.
 * Checks that the client presented a valid certificate.
 */
export function requireClientCertificate(req: any, res: any, next: any) {
    const cert = req.socket.getPeerCertificate();
    
    if (!cert || Object.keys(cert).length === 0) {
        return res.status(403).json({
            success: false,
            error: 'Client certificate required for this endpoint (mTLS).'
        });
    }

    if (!req.client.authorized) {
        return res.status(403).json({
            success: false,
            error: 'Client certificate validation failed.'
        });
    }

    // Attach certificate info to request for downstream use
    (req as any).clientCert = {
        subject: cert.subject,
        issuer: cert.issuer,
        fingerprint: cert.fingerprint256,
        validFrom: cert.valid_from,
        validTo: cert.valid_to
    };

    next();
}
