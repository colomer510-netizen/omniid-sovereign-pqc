/**
 * OmniID GDPR — Session Manager Module
 * 
 * Manages JWT access tokens and opaque refresh tokens with automatic rotation.
 * Implements device fingerprinting and secure session lifecycle.
 * 
 * GDPR Articles: Art. 32 — Security of processing
 */

import * as crypto from 'crypto';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface TokenPair {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;           // Access token TTL in seconds
    tokenType: 'Bearer';
}

export interface SessionRecord {
    sessionId: string;
    userId: string;
    role: string;
    refreshToken: string;        // Hashed refresh token
    deviceFingerprint: string;   // Hash of device characteristics
    ipAddress: string;           // Partial IP (first 3 octets)
    userAgent: string;
    createdAt: Date;
    lastActiveAt: Date;
    expiresAt: Date;             // Refresh token expiry
    revoked: boolean;
}

export interface AccessTokenPayload {
    sub: string;                 // User DID
    role: string;
    sessionId: string;
    iat: number;
    exp: number;
    fingerprint: string;         // Truncated device fingerprint
}

// ─── Constants ───────────────────────────────────────────────────────────────

const ACCESS_TOKEN_TTL = 15 * 60;          // 15 minutes (seconds)
const REFRESH_TOKEN_TTL = 7 * 24 * 60 * 60; // 7 days (seconds)
const REFRESH_TOKEN_LENGTH = 64;            // Bytes

// ─── In-Memory Session Store ─────────────────────────────────────────────────

const sessions = new Map<string, SessionRecord>();

// ─── JWT Implementation (HS256) ──────────────────────────────────────────────

/**
 * Get the JWT signing secret from environment.
 */
function getJWTSecret(): string {
    const secret = process.env.OMNIID_JWT_SECRET;
    if (!secret || secret.length < 32) {
        throw new Error(
            '[SESSION] OMNIID_JWT_SECRET is not set or too short (minimum 32 characters). ' +
            'Generate with: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"'
        );
    }
    return secret;
}

/**
 * Base64url encode a buffer or string.
 */
function base64url(input: string | Buffer): string {
    const buf = typeof input === 'string' ? Buffer.from(input) : input;
    return buf.toString('base64url');
}

/**
 * Create a JWT (HS256).
 */
function createJWT(payload: AccessTokenPayload): string {
    const header = { alg: 'HS256', typ: 'JWT' };
    const headerB64 = base64url(JSON.stringify(header));
    const payloadB64 = base64url(JSON.stringify(payload));
    const unsigned = `${headerB64}.${payloadB64}`;

    const signature = crypto
        .createHmac('sha256', getJWTSecret())
        .update(unsigned)
        .digest('base64url');

    return `${unsigned}.${signature}`;
}

/**
 * Verify and decode a JWT (HS256).
 */
function verifyJWT(token: string): AccessTokenPayload | null {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;

        const [headerB64, payloadB64, signature] = parts;
        const unsigned = `${headerB64}.${payloadB64}`;

        const expectedSig = crypto
            .createHmac('sha256', getJWTSecret())
            .update(unsigned)
            .digest('base64url');

        // Timing-safe comparison
        if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
            return null;
        }

        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

        // Check expiration
        if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
            return null;
        }

        return payload as AccessTokenPayload;
    } catch {
        return null;
    }
}

// ─── Helper Functions ────────────────────────────────────────────────────────

/**
 * Generate a device fingerprint from request characteristics.
 * Uses a partial hash to balance privacy with security.
 */
function generateDeviceFingerprint(userAgent: string, ip: string): string {
    // Use only the first 3 octets of IPv4 to preserve some privacy
    const partialIP = ip.split('.').slice(0, 3).join('.');
    const raw = `${userAgent}|${partialIP}`;
    return crypto.createHash('sha256').update(raw).digest('hex').substring(0, 16);
}

/**
 * Generate a cryptographically random refresh token.
 */
function generateRefreshToken(): string {
    return crypto.randomBytes(REFRESH_TOKEN_LENGTH).toString('hex');
}

/**
 * Hash a refresh token for storage (never store raw refresh tokens).
 */
function hashRefreshToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
}

// ─── Public API ──────────────────────────────────────────────────────────────

export class SessionManager {
    /**
     * Create a new session and issue a token pair.
     */
    public static createSession(
        userId: string,
        role: string,
        userAgent: string,
        ipAddress: string
    ): TokenPair {
        const sessionId = crypto.randomUUID();
        const fingerprint = generateDeviceFingerprint(userAgent, ipAddress);
        const refreshToken = generateRefreshToken();
        const now = Math.floor(Date.now() / 1000);

        // Create access token
        const accessPayload: AccessTokenPayload = {
            sub: userId,
            role,
            sessionId,
            iat: now,
            exp: now + ACCESS_TOKEN_TTL,
            fingerprint: fingerprint.substring(0, 8) // Truncated in token
        };

        const accessToken = createJWT(accessPayload);

        // Store session record
        const session: SessionRecord = {
            sessionId,
            userId,
            role,
            refreshToken: hashRefreshToken(refreshToken),
            deviceFingerprint: fingerprint,
            ipAddress: ipAddress.split('.').slice(0, 3).join('.') + '.x',
            userAgent: userAgent.substring(0, 200),
            createdAt: new Date(),
            lastActiveAt: new Date(),
            expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL * 1000),
            revoked: false
        };

        sessions.set(sessionId, session);

        return {
            accessToken,
            refreshToken,
            expiresIn: ACCESS_TOKEN_TTL,
            tokenType: 'Bearer'
        };
    }

    /**
     * Verify an access token and return the session info.
     */
    public static verifyAccessToken(token: string): AccessTokenPayload | null {
        const payload = verifyJWT(token);
        if (!payload) return null;

        // Verify session still exists and is not revoked
        const session = sessions.get(payload.sessionId);
        if (!session || session.revoked) return null;

        // Update last active time
        session.lastActiveAt = new Date();

        return payload;
    }

    /**
     * Rotate tokens using a refresh token.
     * The old refresh token is invalidated (token rotation).
     */
    public static refreshSession(
        refreshToken: string,
        userAgent: string,
        ipAddress: string
    ): TokenPair | null {
        const hashedToken = hashRefreshToken(refreshToken);

        // Find the session with this refresh token
        let targetSession: SessionRecord | null = null;
        let targetSessionId: string | null = null;

        for (const [id, session] of sessions.entries()) {
            if (session.refreshToken === hashedToken && !session.revoked) {
                targetSession = session;
                targetSessionId = id;
                break;
            }
        }

        if (!targetSession || !targetSessionId) {
            console.warn('[SESSION] Invalid refresh token used. Possible token reuse attack.');
            return null;
        }

        // Check expiry
        if (new Date() > targetSession.expiresAt) {
            targetSession.revoked = true;
            return null;
        }

        // Verify device fingerprint hasn't drastically changed
        const currentFingerprint = generateDeviceFingerprint(userAgent, ipAddress);
        if (currentFingerprint !== targetSession.deviceFingerprint) {
            console.warn(
                `[SESSION] Device fingerprint mismatch for session ${targetSessionId}. ` +
                `Expected: ${targetSession.deviceFingerprint}, Got: ${currentFingerprint}. ` +
                `Possible session hijacking.`
            );
            // Revoke the session
            targetSession.revoked = true;
            return null;
        }

        // Rotate: Generate new refresh token and invalidate old one
        const newRefreshToken = generateRefreshToken();
        targetSession.refreshToken = hashRefreshToken(newRefreshToken);
        targetSession.lastActiveAt = new Date();

        // Issue new access token
        const now = Math.floor(Date.now() / 1000);
        const accessPayload: AccessTokenPayload = {
            sub: targetSession.userId,
            role: targetSession.role,
            sessionId: targetSessionId,
            iat: now,
            exp: now + ACCESS_TOKEN_TTL,
            fingerprint: currentFingerprint.substring(0, 8)
        };

        return {
            accessToken: createJWT(accessPayload),
            refreshToken: newRefreshToken,
            expiresIn: ACCESS_TOKEN_TTL,
            tokenType: 'Bearer'
        };
    }

    /**
     * Revoke a specific session (logout).
     */
    public static revokeSession(sessionId: string): boolean {
        const session = sessions.get(sessionId);
        if (!session) return false;
        session.revoked = true;
        return true;
    }

    /**
     * Revoke all sessions for a user (force logout everywhere).
     */
    public static revokeAllSessions(userId: string): number {
        let revoked = 0;
        for (const session of sessions.values()) {
            if (session.userId === userId && !session.revoked) {
                session.revoked = true;
                revoked++;
            }
        }
        return revoked;
    }

    /**
     * Get all active sessions for a user.
     */
    public static getUserSessions(userId: string): SessionRecord[] {
        const userSessions: SessionRecord[] = [];
        for (const session of sessions.values()) {
            if (session.userId === userId && !session.revoked) {
                // Don't expose the hashed refresh token
                userSessions.push({
                    ...session,
                    refreshToken: '[HIDDEN]'
                });
            }
        }
        return userSessions;
    }

    /**
     * Cleanup expired sessions.
     */
    public static cleanup(): void {
        const now = new Date();
        for (const [id, session] of sessions.entries()) {
            if (session.revoked || now > session.expiresAt) {
                sessions.delete(id);
            }
        }
    }
}

// Run cleanup every 15 minutes
setInterval(() => SessionManager.cleanup(), 15 * 60 * 1000);
