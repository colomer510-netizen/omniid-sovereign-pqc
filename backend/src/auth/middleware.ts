/**
 * OmniID GDPR — Authentication Middleware Module
 * 
 * Express middleware functions for authenticating requests,
 * enforcing MFA, and checking permissions.
 * 
 * GDPR Articles: Art. 32 — Security of processing
 */

import { Request, Response, NextFunction } from 'express';
import { SessionManager, AccessTokenPayload } from './session-manager';
import { RBACEngine, Permission, Role } from './rbac';

// ─── Extended Request Type ───────────────────────────────────────────────────

export interface AuthenticatedRequest extends Request {
    user?: {
        did: string;
        role: string;
        sessionId: string;
        fingerprint: string;
    };
}

// ─── Authentication Middleware ────────────────────────────────────────────────

/**
 * Require authentication via Bearer token.
 * Extracts and verifies the JWT access token from the Authorization header.
 */
export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
            success: false,
            error: 'Authentication required. Provide a Bearer token in the Authorization header.'
        });
        return;
    }

    const token = authHeader.substring(7); // Remove 'Bearer '
    const payload = SessionManager.verifyAccessToken(token);

    if (!payload) {
        res.status(401).json({
            success: false,
            error: 'Invalid or expired access token. Please refresh your session.'
        });
        return;
    }

    // Attach user info to request
    req.user = {
        did: payload.sub,
        role: payload.role,
        sessionId: payload.sessionId,
        fingerprint: payload.fingerprint
    };

    next();
}

/**
 * Optional authentication — populates req.user if token present, but doesn't block.
 */
export function optionalAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const payload = SessionManager.verifyAccessToken(token);

        if (payload) {
            req.user = {
                did: payload.sub,
                role: payload.role,
                sessionId: payload.sessionId,
                fingerprint: payload.fingerprint
            };
        }
    }

    next();
}

// ─── Authorization Middleware ─────────────────────────────────────────────────

/**
 * Require a specific permission.
 * Must be used AFTER requireAuth middleware.
 */
export function requirePermission(permission: Permission) {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        if (!req.user) {
            res.status(401).json({
                success: false,
                error: 'Authentication required.'
            });
            return;
        }

        if (!RBACEngine.hasPermission(req.user.role, permission)) {
            res.status(403).json({
                success: false,
                error: `Insufficient permissions. Required: ${permission}`,
                yourRole: req.user.role,
                yourPermissions: RBACEngine.getPermissions(req.user.role as Role)
            });
            return;
        }

        next();
    };
}

/**
 * Require one of multiple permissions.
 */
export function requireAnyPermission(...permissions: Permission[]) {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        if (!req.user) {
            res.status(401).json({
                success: false,
                error: 'Authentication required.'
            });
            return;
        }

        const hasAny = permissions.some(p => RBACEngine.hasPermission(req.user!.role, p));
        if (!hasAny) {
            res.status(403).json({
                success: false,
                error: `Insufficient permissions. Required one of: ${permissions.join(', ')}`,
                yourRole: req.user.role
            });
            return;
        }

        next();
    };
}

/**
 * Require a specific role.
 */
export function requireRole(...roles: Role[]) {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        if (!req.user) {
            res.status(401).json({
                success: false,
                error: 'Authentication required.'
            });
            return;
        }

        if (!roles.includes(req.user.role as Role)) {
            res.status(403).json({
                success: false,
                error: `Access restricted to roles: ${roles.join(', ')}`,
                yourRole: req.user.role
            });
            return;
        }

        next();
    };
}

/**
 * Require that the authenticated user is accessing their own resource.
 * Compares the authenticated user's DID with a DID in the request path or body.
 */
export function requireSelfOrAdmin(didParam: string = 'did') {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        if (!req.user) {
            res.status(401).json({
                success: false,
                error: 'Authentication required.'
            });
            return;
        }

        const targetDid = req.params[didParam] || req.body[didParam];

        // Admins and DPOs can access any user's data
        if (req.user.role === Role.ADMIN || req.user.role === Role.DPO) {
            next();
            return;
        }

        // Citizens and Operators can only access their own data
        if (targetDid && targetDid !== req.user.did) {
            res.status(403).json({
                success: false,
                error: 'You can only access your own data.'
            });
            return;
        }

        next();
    };
}

// ─── CSRF Protection ─────────────────────────────────────────────────────────

/**
 * CSRF token generation and validation for state-changing requests.
 * Uses the double-submit cookie pattern.
 */
export function csrfProtection(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
    // Skip for API-only requests with Bearer auth (not cookie-based)
    if (req.headers.authorization?.startsWith('Bearer ')) {
        next();
        return;
    }

    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
        const csrfCookie = req.cookies?.omniid_csrf;
        const csrfHeader = req.headers['x-csrf-token'] as string;

        if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
            res.status(403).json({
                success: false,
                error: 'CSRF token validation failed.'
            });
            return;
        }
    }

    next();
}
