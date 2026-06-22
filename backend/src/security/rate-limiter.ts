/**
 * OmniID GDPR — Rate Limiter Module
 * 
 * Configures per-endpoint rate limiting to prevent brute force attacks,
 * credential stuffing, and abuse of GDPR rights endpoints.
 * 
 * GDPR Articles: Art. 32 — Security measures against unauthorized access
 */

import rateLimit from 'express-rate-limit';
import { RequestHandler } from 'express';

/**
 * General API rate limiter.
 * 1000 requests per 15-minute window.
 */
export const generalLimiter: RequestHandler = rateLimit({
    windowMs: 15 * 60 * 1000,   // 15 minutes
    max: 1000,
    standardHeaders: true,       // Return rate limit info in headers
    legacyHeaders: false,
    message: {
        success: false,
        error: 'Too many requests. Please try again later.',
        retryAfter: '15 minutes'
    },
    keyGenerator: (req) => {
        // Use X-Forwarded-For if behind a proxy, fallback to IP
        return (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() 
            || req.ip 
            || 'unknown';
    }
});

/**
 * Login rate limiter.
 * 5 attempts per 15-minute window to prevent brute force.
 */
export const loginLimiter: RequestHandler = rateLimit({
    windowMs: 15 * 60 * 1000,   // 15 minutes
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        error: 'Too many login attempts. Account temporarily locked.',
        retryAfter: '15 minutes',
        action: 'ACCOUNT_LOCKED_TEMP'
    },
    keyGenerator: (req) => {
        // Rate limit by both IP and username to prevent distributed attacks
        const username = req.body?.username || req.body?.email || '';
        const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() 
            || req.ip || 'unknown';
        return `login:${ip}:${username}`;
    },
    skipSuccessfulRequests: true  // Don't count successful logins
});

/**
 * Identity issuance rate limiter.
 * 10 issuances per hour per IP/operator.
 */
export const issuanceLimiter: RequestHandler = rateLimit({
    windowMs: 60 * 60 * 1000,   // 1 hour
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        error: 'Issuance rate limit exceeded. Maximum 10 issuances per hour.',
        retryAfter: '1 hour'
    },
    keyGenerator: (req) => {
        const operatorId = (req as any).user?.did || 'anonymous';
        const ip = req.ip || 'unknown';
        return `issue:${operatorId}:${ip}`;
    }
});

/**
 * Verification rate limiter.
 * 100 verifications per hour.
 */
export const verificationLimiter: RequestHandler = rateLimit({
    windowMs: 60 * 60 * 1000,   // 1 hour
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        error: 'Verification rate limit exceeded.',
        retryAfter: '1 hour'
    }
});

/**
 * GDPR erasure rate limiter.
 * 1 erasure request per 24 hours.
 */
export const erasureLimiter: RequestHandler = rateLimit({
    windowMs: 24 * 60 * 60 * 1000,  // 24 hours
    max: 1,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        error: 'Only one erasure request permitted per 24 hours.',
        retryAfter: '24 hours'
    },
    keyGenerator: (req) => {
        const userId = (req as any).user?.did || req.ip || 'unknown';
        return `erase:${userId}`;
    }
});

/**
 * GDPR data export rate limiter.
 * 5 downloads per hour.
 */
export const exportLimiter: RequestHandler = rateLimit({
    windowMs: 60 * 60 * 1000,  // 1 hour
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        error: 'Export rate limit exceeded. Maximum 5 exports per hour.',
        retryAfter: '1 hour'
    },
    keyGenerator: (req) => {
        const userId = (req as any).user?.did || req.ip || 'unknown';
        return `export:${userId}`;
    }
});

/**
 * MFA verification rate limiter.
 * 5 attempts per 5-minute window.
 */
export const mfaLimiter: RequestHandler = rateLimit({
    windowMs: 5 * 60 * 1000,   // 5 minutes
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        error: 'Too many MFA verification attempts. Please wait.',
        retryAfter: '5 minutes'
    },
    keyGenerator: (req) => {
        const userId = (req as any).user?.did || req.ip || 'unknown';
        return `mfa:${userId}`;
    }
});
