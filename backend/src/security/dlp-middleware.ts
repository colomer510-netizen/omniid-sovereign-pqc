/**
 * OmniID GDPR — Data Loss Prevention (DLP) Middleware
 * 
 * Intercepts outgoing HTTP responses to detect and prevent accidental
 * leakage of sensitive PII data outside authorized endpoints.
 * 
 * GDPR Articles: Art. 5(1)(f), Art. 32 — Data confidentiality measures
 */

import { Request, Response, NextFunction } from 'express';

// ─── Sensitive Data Patterns ─────────────────────────────────────────────────

/**
 * Regex patterns that indicate potential PII leakage in response bodies.
 */
const SENSITIVE_PATTERNS = [
    {
        name: 'Private Key (ML-DSA)',
        pattern: /ML-DSA-65_SK_[A-Za-z0-9_-]+/g,
        severity: 'CRITICAL'
    },
    {
        name: 'Raw Biometric Template',
        pattern: /"biometricTemplate"\s*:\s*\[[\d,\s]+\]/g,
        severity: 'CRITICAL'
    },
    {
        name: 'Password Hash',
        pattern: /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/g,
        severity: 'HIGH'
    },
    {
        name: 'Master Encryption Key',
        pattern: /OMNIID_MASTER_ENCRYPTION_KEY/g,
        severity: 'CRITICAL'
    },
    {
        name: 'TOTP Secret',
        pattern: /"totpSecret"\s*:\s*"[A-Z2-7]+=*"/g,
        severity: 'CRITICAL'
    },
    {
        name: 'JWT Refresh Token',
        pattern: /"refreshToken"\s*:\s*"[A-Za-z0-9_-]{64,}"/g,
        severity: 'HIGH'
    }
];

/**
 * Endpoints that are authorized to return sensitive data.
 * DLP will not flag these routes.
 */
const AUTHORIZED_PII_ENDPOINTS = [
    '/api/v1/identities/issue',     // Returns credential to holder
    '/api/v1/gdpr/my-data',         // GDPR data access right
    '/api/v1/gdpr/export'           // GDPR data portability
];

// ─── DLP Middleware ──────────────────────────────────────────────────────────

interface DLPAlert {
    timestamp: Date;
    endpoint: string;
    method: string;
    patternName: string;
    severity: string;
    ip: string;
    requestId?: string;
}

const dlpAlerts: DLPAlert[] = [];

/**
 * Data Loss Prevention middleware.
 * 
 * Intercepts res.json() calls to scan response bodies for sensitive data.
 * On non-authorized endpoints, it redacts the sensitive data and logs an alert.
 */
export function dlpMiddleware(req: Request, res: Response, next: NextFunction): void {
    // Store original json method
    const originalJson = res.json.bind(res);

    // Override res.json to intercept responses
    res.json = function(body: any): Response {
        // Skip DLP for non-API routes or authorized endpoints
        const isAuthorized = AUTHORIZED_PII_ENDPOINTS.some(ep => req.path.includes(ep));
        
        if (body && typeof body === 'object' && !isAuthorized) {
            const bodyStr = JSON.stringify(body);
            
            for (const pattern of SENSITIVE_PATTERNS) {
                if (pattern.pattern.test(bodyStr)) {
                    // Reset regex lastIndex
                    pattern.pattern.lastIndex = 0;
                    
                    const alert: DLPAlert = {
                        timestamp: new Date(),
                        endpoint: req.path,
                        method: req.method,
                        patternName: pattern.name,
                        severity: pattern.severity,
                        ip: (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || 'unknown',
                        requestId: (req as any).requestId
                    };
                    
                    dlpAlerts.push(alert);
                    
                    console.error(
                        `[DLP] 🚨 ALERT: ${pattern.severity} — Detected "${pattern.name}" in response from ` +
                        `${req.method} ${req.path}. Data has been redacted.`
                    );

                    // Redact the sensitive data from the response
                    body = redactSensitiveData(body, pattern.name);
                }
                // Reset regex lastIndex after test
                pattern.pattern.lastIndex = 0;
            }
        }

        // Also check for private keys being accidentally returned
        if (body && typeof body === 'object' && !isAuthorized) {
            body = deepRedactKeys(body, [
                'privateKey', 'private_key', 'secret', 'password',
                'totpSecret', 'totp_secret', 'masterKey', 'master_key',
                'refreshToken', 'originalTemplate'
            ]);
        }

        return originalJson(body);
    };

    next();
}

/**
 * Redact detected sensitive data by replacing values with a redaction marker.
 */
function redactSensitiveData(obj: any, patternName: string): any {
    const str = JSON.stringify(obj);
    const redacted = str.replace(
        SENSITIVE_PATTERNS.find(p => p.name === patternName)!.pattern,
        `"[REDACTED by DLP: ${patternName}]"`
    );
    // Reset regex lastIndex
    SENSITIVE_PATTERNS.forEach(p => p.pattern.lastIndex = 0);
    
    try {
        return JSON.parse(redacted);
    } catch {
        return obj; // If JSON parse fails, return original
    }
}

/**
 * Deep-scan an object and redact specific key names.
 */
function deepRedactKeys(obj: any, sensitiveKeys: string[]): any {
    if (obj === null || obj === undefined) return obj;
    if (typeof obj !== 'object') return obj;

    if (Array.isArray(obj)) {
        return obj.map(item => deepRedactKeys(item, sensitiveKeys));
    }

    const redacted: any = {};
    for (const [key, value] of Object.entries(obj)) {
        if (sensitiveKeys.includes(key)) {
            redacted[key] = '[REDACTED by DLP]';
        } else if (typeof value === 'object' && value !== null) {
            redacted[key] = deepRedactKeys(value, sensitiveKeys);
        } else {
            redacted[key] = value;
        }
    }
    return redacted;
}

/**
 * Get DLP alerts for security review.
 */
export function getDLPAlerts(since?: Date): DLPAlert[] {
    if (since) {
        return dlpAlerts.filter(a => a.timestamp >= since);
    }
    return [...dlpAlerts];
}

/**
 * Console output sanitizer.
 * Wraps console.log to prevent accidental PII leakage in server logs.
 */
export function sanitizeConsoleOutput(): void {
    const originalLog = console.log;
    const originalError = console.error;
    const originalWarn = console.warn;

    const sanitize = (args: any[]): any[] => {
        return args.map(arg => {
            if (typeof arg === 'string') {
                let sanitized = arg;
                for (const pattern of SENSITIVE_PATTERNS) {
                    sanitized = sanitized.replace(pattern.pattern, `[REDACTED:${pattern.name}]`);
                    pattern.pattern.lastIndex = 0;
                }
                return sanitized;
            }
            return arg;
        });
    };

    console.log = (...args: any[]) => originalLog(...sanitize(args));
    console.error = (...args: any[]) => originalError(...sanitize(args));
    console.warn = (...args: any[]) => originalWarn(...sanitize(args));
}
