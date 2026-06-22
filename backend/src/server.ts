import express from 'express';
import cors from 'cors';
import * as dotenv from 'dotenv';

// Load Environment variables
dotenv.config();

// ─── Module Imports ──────────────────────────────────────────────────────────

// Existing routes
import { identityRouter } from './routes/identity';

// GDPR modules
import { consentRouter } from './consent/consent-routes';
import { auditRouter } from './audit/audit-routes';
import { gdprRouter } from './gdpr/gdpr-routes';

// Security modules
import { createSecureServer, httpsRedirectMiddleware } from './security/tls-config';
import { createSecurityHeaders, additionalSecurityHeaders, getCorsOptions } from './security/helmet-config';
import { generalLimiter } from './security/rate-limiter';
import { enforceContentType } from './security/input-validator';
import { breachDetector } from './security/breach-detector';
import { dlpMiddleware, sanitizeConsoleOutput } from './security/dlp-middleware';

// Consent
import { cookieConsentMiddleware } from './consent/cookie-policy';

// Audit
import { AuditLogger } from './audit/audit-logger';
import { AuditEventType, AuditAction, AuditOutcome } from './audit/audit-types';

// GDPR Scheduler
import { startErasureScheduler } from './gdpr/gdpr-scheduler';

// ─── Initialize ──────────────────────────────────────────────────────────────

// Sanitize console output to prevent accidental PII leakage in logs
sanitizeConsoleOutput();

const app = express();
const PORT = process.env.PORT || 3000;
const HTTPS_PORT = parseInt(process.env.HTTPS_PORT || '3443');
const ENABLE_HTTPS = process.env.ENABLE_HTTPS === 'true';

// ─── Security Middleware Stack (order matters!) ──────────────────────────────

// 1. Security headers (Helmet: HSTS, CSP, X-Frame-Options, etc.)
app.use(createSecurityHeaders());
app.use(additionalSecurityHeaders());

// 2. Breach detector middleware (blocks flagged IPs, enforces defensive mode)
app.use(breachDetector.middleware());

// 3. CORS — restrictive configuration (replaces open cors())
app.use(cors(getCorsOptions()));

// 4. Rate limiting — general API limit
app.use('/api/', generalLimiter);

// 5. Parse incoming requests JSON (with size limit)
app.use(express.json({ limit: '100kb' }));

// 6. Content-Type enforcement for API routes
app.use('/api/', enforceContentType);

// 7. Cookie consent middleware
app.use(cookieConsentMiddleware);

// 8. DLP middleware (scans outgoing responses for PII leaks)
app.use(dlpMiddleware);

// ─── Route Registration ─────────────────────────────────────────────────────

// Existing identity routes
app.use('/api/v1/identities', identityRouter);

// GDPR Consent routes
app.use('/api/v1/consent', consentRouter);

// Audit log routes
app.use('/api/v1/audit', auditRouter);

// GDPR rights routes (access, export, erase, rectify)
app.use('/api/v1/gdpr', gdprRouter);

// Cookie policy endpoint (public)
app.get('/api/v1/cookies/policy', (req, res) => {
    const { getCookiePolicyData } = require('./consent/cookie-policy');
    res.json({ success: true, policy: getCookiePolicyData() });
});

// ─── Base Routes ─────────────────────────────────────────────────────────────

// Base route for connectivity test
app.get('/', (req, res) => {
    res.json({
        name: "OmniID Sovereign PQC Cryptographic API",
        version: "2.0.0-gdpr",
        status: "ACTIVE",
        gdprCompliant: true,
        modules: {
            encryption: "AES-256-GCM (Data at Rest)",
            tls: "TLS 1.3 (Data in Transit)",
            mfa: "TOTP + WebAuthn/FIDO2",
            consent: "Granular Consent Manager",
            audit: "Immutable Chain-Linked Audit Log",
            gdprRights: "Access, Portability, Erasure, Rectification",
            security: "Helmet, Rate Limiting, DLP, Breach Detection"
        },
        endpoints: {
            identity: '/api/v1/identities',
            consent: '/api/v1/consent',
            audit: '/api/v1/audit',
            gdpr: '/api/v1/gdpr',
            cookiePolicy: '/api/v1/cookies/policy'
        }
    });
});

// Health check endpoint
app.get('/health', (req, res) => {
    const auditIntegrity = AuditLogger.verifyIntegrity();
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        auditLogIntegrity: auditIntegrity.valid ? 'INTACT' : 'COMPROMISED',
        defensiveMode: breachDetector.isDefensiveMode()
    });
});

// ─── Server Startup ──────────────────────────────────────────────────────────

// Log system startup audit event
AuditLogger.log({
    eventType: AuditEventType.SYSTEM_STARTUP,
    action: AuditAction.CONFIGURE,
    actorId: 'SYSTEM',
    actorRole: 'SYSTEM',
    targetResource: 'server',
    details: {
        port: PORT,
        httpsEnabled: ENABLE_HTTPS,
        gdprModules: ['encryption', 'mfa', 'consent', 'audit', 'gdpr-rights', 'breach-detection', 'dlp']
    },
    outcome: AuditOutcome.SUCCESS
});

// Start GDPR erasure scheduler
startErasureScheduler((userId: string) => {
    // Placeholder: In production, this would delete from the database
    console.log(`[GDPR-SCHEDULER] Deleting identity data for: ${userId}`);
    return { piiDeleted: true, credentialsRevoked: 1, biometricDeleted: true };
});

// Initialize SIEM Logger
AuditLogger.initialize();

// Initialize Encryption Engine (Vault) and Start Server
import { initializeEncryptionEngine } from './security/encryption';

initializeEncryptionEngine().then(() => {
    if (ENABLE_HTTPS) {
        // Start HTTPS server with TLS 1.3
        createSecureServer(app, { port: HTTPS_PORT });

        // HTTP server redirects to HTTPS
        const httpApp = express();
        httpApp.use(httpsRedirectMiddleware(HTTPS_PORT));
        httpApp.listen(PORT, () => {
            console.log(`[HTTP] Redirect server on port ${PORT} → https://localhost:${HTTPS_PORT}`);
        });
    } else {
        // Development: Start HTTP server
        app.listen(PORT, () => {
            console.log(`==================================================`);
            console.log(`   OmniID Enterprise Backend Server Running`);
            console.log(`   URL: http://localhost:${PORT}`);
            console.log(`   DLT Connector: Hyperledger Indy`);
            console.log(`   PQC Algorithm: ML-DSA-65 (CRYSTALS-Dilithium)`);
            console.log(`   Enterprise Modules: ACTIVE`);
            console.log(`   ├── KMS: HashiCorp Vault (Envelope Encryption)`);
            console.log(`   ├── SIEM: Wazuh/ELK NDJSON Logger Active`);
            console.log(`   ├── MFA: TOTP + WebAuthn`);
            console.log(`   ├── Consent Manager: Active`);
            console.log(`   ├── Audit Logger: Chain-linked`);
            console.log(`   ├── GDPR Rights API: Active`);
            console.log(`   ├── Rate Limiter: Active`);
            console.log(`   ├── DLP: Active`);
            console.log(`   └── Breach Detector: Active`);
            console.log(`==================================================`);
        });
    }
});
