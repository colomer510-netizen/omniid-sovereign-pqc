/**
 * OmniID GDPR — HTTP Security Headers Configuration
 * 
 * Configures comprehensive security headers using Helmet.js to prevent
 * common web vulnerabilities (XSS, clickjacking, MIME sniffing, etc.)
 * 
 * GDPR Articles: Art. 32 — Technical measures for data protection
 */

import helmet from 'helmet';
import { RequestHandler } from 'express';

/**
 * Create the Helmet middleware stack with hardened security headers.
 */
export function createSecurityHeaders(): RequestHandler {
    return helmet({
        // Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
        // Forces HTTPS for 2 years with preload eligibility
        hsts: {
            maxAge: 63072000,       // 2 years in seconds
            includeSubDomains: true,
            preload: true
        },

        // Content-Security-Policy: Strict policy preventing XSS and injection
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'", "https://fonts.googleapis.com"],
                fontSrc: ["https://fonts.gstatic.com"],
                imgSrc: ["'self'", "data:"],
                connectSrc: ["'self'"],
                frameAncestors: ["'none'"],      // Prevent embedding in iframes
                baseUri: ["'self'"],              // Prevent base tag hijacking
                formAction: ["'self'"],           // Restrict form submissions
                objectSrc: ["'none'"],            // Block Flash/Java plugins
                scriptSrcAttr: ["'none'"],        // Block inline event handlers
                upgradeInsecureRequests: []       // Auto-upgrade HTTP to HTTPS
            }
        },

        // X-Content-Type-Options: nosniff
        // Prevents MIME type sniffing
        noSniff: undefined, // helmet enables this by default

        // X-Frame-Options: DENY
        // Prevents clickjacking (also handled by CSP frame-ancestors)
        frameguard: {
            action: 'deny'
        },

        // Referrer-Policy: strict-origin-when-cross-origin
        // Controls how much referrer info is shared
        referrerPolicy: {
            policy: 'strict-origin-when-cross-origin'
        },

        // X-DNS-Prefetch-Control: off
        // Disables DNS prefetching for privacy
        dnsPrefetchControl: {
            allow: false
        },

        // X-Permitted-Cross-Domain-Policies: none
        // Prevents Adobe Flash/Acrobat cross-domain requests
        permittedCrossDomainPolicies: {
            permittedPolicies: 'none'
        },

        // Cross-Origin-Opener-Policy: same-origin
        crossOriginOpenerPolicy: {
            policy: 'same-origin'
        },

        // Cross-Origin-Resource-Policy: same-origin
        crossOriginResourcePolicy: {
            policy: 'same-origin'
        },

        // Cross-Origin-Embedder-Policy
        crossOriginEmbedderPolicy: false, // Can break legitimate embeds, disable unless needed

        // X-XSS-Protection: 0 (disabled in favor of CSP)
        // Modern recommendation: disable legacy XSS filter, rely on CSP instead
        xXssProtection: false
    });
}

/**
 * Additional custom security headers not covered by Helmet.
 */
export function additionalSecurityHeaders(): RequestHandler {
    return (req, res, next) => {
        // Permissions-Policy: Restrict browser feature access
        res.setHeader('Permissions-Policy',
            'camera=(), microphone=(), geolocation=(), payment=(), ' +
            'usb=(), magnetometer=(), gyroscope=(), accelerometer=()'
        );

        // Cache-Control: Prevent caching of sensitive API responses
        if (req.path.startsWith('/api/')) {
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }

        // X-Request-ID: Add unique request identifier for tracing
        const requestId = req.headers['x-request-id'] || 
            `omniid-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        res.setHeader('X-Request-ID', requestId);
        (req as any).requestId = requestId;

        // Remove X-Powered-By (helmet does this too, but ensure it)
        res.removeHeader('X-Powered-By');

        next();
    };
}

/**
 * CORS configuration for production use.
 * Replaces the open cors() in the current server.ts
 */
export function getCorsOptions() {
    const allowedOrigins = process.env.CORS_ALLOWED_ORIGINS
        ? process.env.CORS_ALLOWED_ORIGINS.split(',').map(s => s.trim())
        : ['http://localhost:8000', 'http://localhost:3000', 'https://localhost:3443', 'http://localhost:8080', 'http://127.0.0.1:8080'];

    return {
        origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
            // Allow requests with no origin (mobile apps, curl, server-to-server)
            if (!origin) return callback(null, true);

            if (allowedOrigins.includes(origin)) {
                callback(null, true);
            } else {
                console.warn(`[CORS] Blocked request from unauthorized origin: ${origin}`);
                callback(new Error('CORS: Origin not allowed'));
            }
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-CSRF-Token'],
        exposedHeaders: ['X-Request-ID'],
        maxAge: 600, // 10 minutes preflight cache
        optionsSuccessStatus: 204
    };
}
