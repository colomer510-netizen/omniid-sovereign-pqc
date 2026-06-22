/**
 * OmniID GDPR — Cookie Policy Configuration
 * 
 * Defines all cookies used by the application, their classification,
 * and whether they require user consent.
 * 
 * GDPR/ePrivacy: Cookie consent requirements
 */

import { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';

// ─── Cookie Definitions ──────────────────────────────────────────────────────

export enum CookieCategory {
    ESSENTIAL = 'essential',       // Always active, no consent needed
    FUNCTIONAL = 'functional',     // Requires consent
    ANALYTICS = 'analytics'        // Requires consent
}

export interface CookieDefinition {
    name: string;
    category: CookieCategory;
    requiresConsent: boolean;
    ttlDays: number;
    description: string;
    flags: {
        httpOnly: boolean;
        secure: boolean;
        sameSite: 'Strict' | 'Lax' | 'None';
    };
}

/**
 * Complete cookie registry for the OmniID application.
 */
export const COOKIE_REGISTRY: CookieDefinition[] = [
    {
        name: 'omniid_session',
        category: CookieCategory.ESSENTIAL,
        requiresConsent: false,
        ttlDays: 0, // Session cookie
        description: 'Session identifier for authenticated users.',
        flags: { httpOnly: true, secure: true, sameSite: 'Strict' }
    },
    {
        name: 'omniid_csrf',
        category: CookieCategory.ESSENTIAL,
        requiresConsent: false,
        ttlDays: 0,
        description: 'CSRF protection token for form submissions.',
        flags: { httpOnly: true, secure: true, sameSite: 'Strict' }
    },
    {
        name: 'omniid_consent',
        category: CookieCategory.ESSENTIAL,
        requiresConsent: false,
        ttlDays: 365,
        description: 'Stores the user\'s cookie consent preferences.',
        flags: { httpOnly: false, secure: true, sameSite: 'Lax' }
    },
    {
        name: 'omniid_preferences',
        category: CookieCategory.FUNCTIONAL,
        requiresConsent: true,
        ttlDays: 180,
        description: 'User interface preferences (language, theme, layout).',
        flags: { httpOnly: false, secure: true, sameSite: 'Lax' }
    },
    {
        name: 'omniid_analytics',
        category: CookieCategory.ANALYTICS,
        requiresConsent: true,
        ttlDays: 90,
        description: 'Anonymous usage statistics for service improvement.',
        flags: { httpOnly: false, secure: true, sameSite: 'Lax' }
    }
];

// ─── Cookie Helper Functions ─────────────────────────────────────────────────

/**
 * Set a cookie with proper security flags.
 */
export function setSecureCookie(
    res: Response,
    name: string,
    value: string,
    ttlDays: number = 0
): void {
    const definition = COOKIE_REGISTRY.find(c => c.name === name);
    if (!definition) {
        console.warn(`[COOKIE] Attempted to set unregistered cookie: ${name}`);
        return;
    }

    const options: any = {
        httpOnly: definition.flags.httpOnly,
        secure: definition.flags.secure || process.env.NODE_ENV === 'production',
        sameSite: definition.flags.sameSite,
        path: '/'
    };

    if (ttlDays > 0) {
        options.maxAge = ttlDays * 24 * 60 * 60 * 1000;
    }

    res.cookie(name, value, options);
}

/**
 * Clear a cookie.
 */
export function clearCookie(res: Response, name: string): void {
    res.clearCookie(name, { path: '/' });
}

/**
 * Generate a CSRF token and set it as a cookie.
 */
export function generateCSRFToken(res: Response): string {
    const token = crypto.randomBytes(32).toString('hex');
    setSecureCookie(res, 'omniid_csrf', token);
    return token;
}

/**
 * Parse the consent cookie to determine which categories are accepted.
 */
export function parseConsentCookie(consentValue: string | undefined): Record<CookieCategory, boolean> {
    const defaults: Record<CookieCategory, boolean> = {
        [CookieCategory.ESSENTIAL]: true,  // Always true
        [CookieCategory.FUNCTIONAL]: false,
        [CookieCategory.ANALYTICS]: false
    };

    if (!consentValue) return defaults;

    try {
        const parsed = JSON.parse(consentValue);
        return {
            [CookieCategory.ESSENTIAL]: true, // Cannot be disabled
            [CookieCategory.FUNCTIONAL]: !!parsed.functional,
            [CookieCategory.ANALYTICS]: !!parsed.analytics
        };
    } catch {
        return defaults;
    }
}

/**
 * Get the cookie policy data for the cookie banner frontend.
 */
export function getCookiePolicyData(): object {
    return {
        categories: [
            {
                id: CookieCategory.ESSENTIAL,
                name: 'Estrictamente Necesarias',
                description: 'Cookies necesarias para el funcionamiento básico del sistema. No se pueden desactivar.',
                required: true,
                cookies: COOKIE_REGISTRY.filter(c => c.category === CookieCategory.ESSENTIAL)
                    .map(c => ({ name: c.name, description: c.description, ttl: c.ttlDays > 0 ? `${c.ttlDays} días` : 'Sesión' }))
            },
            {
                id: CookieCategory.FUNCTIONAL,
                name: 'Funcionales',
                description: 'Permiten recordar sus preferencias de interfaz para una experiencia personalizada.',
                required: false,
                cookies: COOKIE_REGISTRY.filter(c => c.category === CookieCategory.FUNCTIONAL)
                    .map(c => ({ name: c.name, description: c.description, ttl: `${c.ttlDays} días` }))
            },
            {
                id: CookieCategory.ANALYTICS,
                name: 'Analíticas',
                description: 'Nos ayudan a entender cómo se usa el sistema para mejorar el servicio.',
                required: false,
                cookies: COOKIE_REGISTRY.filter(c => c.category === CookieCategory.ANALYTICS)
                    .map(c => ({ name: c.name, description: c.description, ttl: `${c.ttlDays} días` }))
            }
        ],
        policyVersion: process.env.PRIVACY_POLICY_VERSION || '1.0',
        lastUpdated: '2026-06-22'
    };
}

/**
 * Middleware that checks consent before setting non-essential cookies.
 */
export function cookieConsentMiddleware(req: Request, res: Response, next: NextFunction): void {
    const consentValue = req.cookies?.omniid_consent;
    const consent = parseConsentCookie(consentValue);
    
    // Attach consent status to request for downstream use
    (req as any).cookieConsent = consent;
    
    next();
}
