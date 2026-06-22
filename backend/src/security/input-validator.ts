/**
 * OmniID GDPR — Input Validation & Sanitization Module
 * 
 * Validates and sanitizes all incoming data using Zod schemas.
 * Prevents injection attacks (SQL, NoSQL, XSS) at the API boundary.
 * 
 * GDPR Articles: Art. 32 — Technical measures for data integrity
 */

import { z } from 'zod';
import { Request, Response, NextFunction } from 'express';

// ─── Common Validators ──────────────────────────────────────────────────────

/**
 * Sanitize a string by removing potentially dangerous characters.
 * Strips HTML tags and common injection patterns.
 */
function sanitizeString(input: string): string {
    return input
        .replace(/<[^>]*>/g, '')                    // Strip HTML tags
        .replace(/[<>'"`;(){}[\]]/g, '')            // Remove dangerous characters
        .replace(/javascript:/gi, '')               // Remove JS protocol
        .replace(/on\w+\s*=/gi, '')                 // Remove inline event handlers
        .replace(/\$\{.*?\}/g, '')                  // Remove template literals
        .replace(/\$(?:where|gt|lt|gte|lte|ne|in|nin|or|and|not|regex)/gi, '') // NoSQL injection
        .trim();
}

/**
 * Sanitized string type — applies sanitization as a Zod transform.
 */
const sanitizedString = (minLen: number = 1, maxLen: number = 255) =>
    z.string()
        .min(minLen, `Minimum ${minLen} characters required`)
        .max(maxLen, `Maximum ${maxLen} characters allowed`)
        .transform(sanitizeString);

// ─── Schema Definitions ─────────────────────────────────────────────────────

/**
 * Schema for identity issuance (POST /api/v1/identities/issue)
 */
export const issueIdentitySchema = z.object({
    fullName: sanitizedString(2, 200)
        .refine(val => /^[\p{L}\s\-'.]+$/u.test(val), {
            message: 'Full name contains invalid characters'
        }),
    dob: z.string()
        .regex(/^\d{4}-\d{2}-\d{2}$/, 'Date must be in ISO format YYYY-MM-DD')
        .refine(val => {
            const date = new Date(val);
            const now = new Date();
            return date < now && date > new Date('1900-01-01');
        }, { message: 'Invalid date of birth' }),
    region: sanitizedString(2, 200),
    biometricTemplate: z.array(z.number().int().min(0).max(255))
        .min(4, 'Biometric template must have at least 4 values')
        .max(256, 'Biometric template too large')
});

/**
 * Schema for identity verification (POST /api/v1/identities/verify)
 */
export const verifyIdentitySchema = z.object({
    sdjwt: z.string()
        .min(10)
        .max(10000)
        .refine(val => val.split('.').length === 3, {
            message: 'SD-JWT must have exactly 3 parts (header.payload.signature)'
        }),
    releasedDisclosures: z.array(
        z.string().max(5000)
    ).max(50, 'Too many disclosures'),
    rule: z.enum(['age', 'region', 'full'], {
        errorMap: () => ({ message: 'Rule must be one of: age, region, full' })
    }),
    verificationChallenge: z.string().max(500).optional(),
    holderSignature: z.string().max(5000).optional()
});

/**
 * Schema for login credentials
 */
export const loginSchema = z.object({
    username: sanitizedString(3, 100)
        .refine(val => /^[a-zA-Z0-9._@\-]+$/.test(val), {
            message: 'Username contains invalid characters'
        }),
    password: z.string()
        .min(8, 'Password must be at least 8 characters')
        .max(128, 'Password too long')
});

/**
 * Schema for MFA TOTP verification
 */
export const mfaTotpSchema = z.object({
    code: z.string()
        .length(6, 'TOTP code must be exactly 6 digits')
        .regex(/^\d{6}$/, 'TOTP code must contain only digits'),
    sessionToken: z.string().min(10).max(500)
});

/**
 * Schema for consent grant
 */
export const consentGrantSchema = z.object({
    purposes: z.array(
        z.enum(['identity_issuance', 'biometric_storage', 'analytics', 'marketing', 'functional'])
    ).min(1, 'At least one purpose must be specified'),
    policyVersion: z.string().regex(/^\d+\.\d+$/, 'Policy version must be in X.Y format')
});

/**
 * Schema for GDPR data rectification
 */
export const rectifyDataSchema = z.object({
    field: z.enum(['fullName', 'dob', 'region'], {
        errorMap: () => ({ message: 'Field must be one of: fullName, dob, region' })
    }),
    newValue: sanitizedString(1, 200),
    reason: sanitizedString(10, 1000)
});

/**
 * Schema for DID format validation
 */
export const didSchema = z.string()
    .regex(/^did:omni:[A-Z]\d{6}[A-Z]\d{7}$/, 'Invalid DID format. Expected: did:omni:XNNNNNNXNNNNNNN');

// ─── Validation Middleware Factory ───────────────────────────────────────────

/**
 * Creates an Express middleware that validates request body against a Zod schema.
 * Returns 400 with detailed error messages if validation fails.
 */
export function validateBody(schema: z.ZodSchema): (req: Request, res: Response, next: NextFunction) => void {
    return (req: Request, res: Response, next: NextFunction) => {
        const result = schema.safeParse(req.body);

        if (!result.success) {
            const errors = result.error.errors.map(err => ({
                field: err.path.join('.'),
                message: err.message,
                code: err.code
            }));

            return res.status(400).json({
                success: false,
                error: 'Input validation failed',
                details: errors
            });
        }

        // Replace body with validated and sanitized data
        req.body = result.data;
        next();
    };
}

/**
 * Creates an Express middleware that validates request query parameters.
 */
export function validateQuery(schema: z.ZodSchema): (req: Request, res: Response, next: NextFunction) => void {
    return (req: Request, res: Response, next: NextFunction) => {
        const result = schema.safeParse(req.query);

        if (!result.success) {
            const errors = result.error.errors.map(err => ({
                field: err.path.join('.'),
                message: err.message
            }));

            return res.status(400).json({
                success: false,
                error: 'Query parameter validation failed',
                details: errors
            });
        }

        (req as any).validatedQuery = result.data;
        next();
    };
}

/**
 * Content-Type enforcement middleware.
 * Ensures API endpoints only accept application/json.
 */
export function enforceContentType(req: Request, res: Response, next: NextFunction): void {
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
        const contentType = req.headers['content-type'];
        if (!contentType || !contentType.includes('application/json')) {
            res.status(415).json({
                success: false,
                error: 'Unsupported Media Type. Content-Type must be application/json.'
            });
            return;
        }
    }
    next();
}

/**
 * Request size limiter middleware.
 * Prevents excessively large payloads.
 */
export function limitRequestSize(maxSizeKB: number = 100) {
    return (req: Request, res: Response, next: NextFunction) => {
        const contentLength = parseInt(req.headers['content-length'] || '0');
        if (contentLength > maxSizeKB * 1024) {
            return res.status(413).json({
                success: false,
                error: `Request body too large. Maximum size: ${maxSizeKB}KB.`
            });
        }
        next();
    };
}
