/**
 * OmniID GDPR — TOTP Multi-Factor Authentication Module
 * 
 * Implements Time-based One-Time Password (RFC 6238) for second-factor
 * authentication. Compatible with Google Authenticator, Authy, etc.
 * 
 * GDPR Articles: Art. 32(1)(b) — Ensuring ongoing confidentiality
 */

import * as crypto from 'crypto';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface TOTPSetup {
    secret: string;           // Base32-encoded secret
    otpauthUri: string;       // URI for QR code generation
    recoveryCodes: string[];  // One-time recovery codes
}

export interface TOTPUserRecord {
    secret: string;
    verified: boolean;          // Has the user verified the setup?
    recoveryCodes: string[];    // Remaining unused recovery codes
    recoveryCodesUsed: string[];
    failedAttempts: number;
    lockedUntil?: Date;
    createdAt: Date;
    lastUsedAt?: Date;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const TOTP_PERIOD = 30;          // Seconds per time step
const TOTP_DIGITS = 6;           // Number of digits in the code
const TOTP_ALGORITHM = 'sha1';   // HMAC algorithm (RFC 6238 standard)
const TOTP_WINDOW = 1;           // Accept codes ±1 time step
const RECOVERY_CODE_COUNT = 8;
const RECOVERY_CODE_LENGTH = 8;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// ─── Base32 Encoding/Decoding ────────────────────────────────────────────────

/**
 * Encode a buffer to Base32 string.
 */
function base32Encode(buffer: Buffer): string {
    let bits = '';
    for (const byte of buffer) {
        bits += byte.toString(2).padStart(8, '0');
    }

    let result = '';
    for (let i = 0; i < bits.length; i += 5) {
        const chunk = bits.slice(i, i + 5).padEnd(5, '0');
        result += BASE32_ALPHABET[parseInt(chunk, 2)];
    }

    // Add padding
    while (result.length % 8 !== 0) {
        result += '=';
    }

    return result;
}

/**
 * Decode a Base32 string to Buffer.
 */
function base32Decode(encoded: string): Buffer {
    const cleaned = encoded.replace(/=+$/, '').toUpperCase();
    let bits = '';

    for (const char of cleaned) {
        const index = BASE32_ALPHABET.indexOf(char);
        if (index === -1) throw new Error(`Invalid Base32 character: ${char}`);
        bits += index.toString(2).padStart(5, '0');
    }

    const bytes: number[] = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }

    return Buffer.from(bytes);
}

// ─── TOTP Core Algorithm ─────────────────────────────────────────────────────

/**
 * Generate a TOTP code for a given time.
 * Implements RFC 6238 / RFC 4226 (HOTP).
 */
function generateTOTPCode(secret: string, timeStep: number): string {
    const key = base32Decode(secret);

    // Convert time step to 8-byte big-endian buffer
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeUInt32BE(0, 0);
    timeBuffer.writeUInt32BE(timeStep, 4);

    // HMAC-SHA1
    const hmac = crypto.createHmac(TOTP_ALGORITHM, key);
    hmac.update(timeBuffer);
    const hash = hmac.digest();

    // Dynamic truncation (RFC 4226 Section 5.4)
    const offset = hash[hash.length - 1] & 0x0f;
    const binary =
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);

    const otp = binary % Math.pow(10, TOTP_DIGITS);
    return otp.toString().padStart(TOTP_DIGITS, '0');
}

/**
 * Get the current time step.
 */
function getCurrentTimeStep(): number {
    return Math.floor(Date.now() / 1000 / TOTP_PERIOD);
}

// ─── Public API ──────────────────────────────────────────────────────────────

export class MFATotpEngine {
    /**
     * Generate a new TOTP setup for a user.
     * Returns the secret, QR code URI, and recovery codes.
     */
    public static generateSetup(userId: string, issuer: string = 'OmniID'): TOTPSetup {
        // Generate 20 bytes of random entropy for the secret
        const secretBytes = crypto.randomBytes(20);
        const secret = base32Encode(secretBytes);

        // Generate otpauth:// URI for QR code scanning
        const encodedIssuer = encodeURIComponent(issuer);
        const encodedUser = encodeURIComponent(userId);
        const otpauthUri = `otpauth://totp/${encodedIssuer}:${encodedUser}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_PERIOD}`;

        // Generate one-time recovery codes
        const recoveryCodes = MFATotpEngine.generateRecoveryCodes();

        return {
            secret,
            otpauthUri,
            recoveryCodes
        };
    }

    /**
     * Generate a set of one-time recovery codes.
     */
    public static generateRecoveryCodes(count: number = RECOVERY_CODE_COUNT): string[] {
        const codes: string[] = [];
        for (let i = 0; i < count; i++) {
            const code = crypto.randomBytes(RECOVERY_CODE_LENGTH)
                .toString('hex')
                .substring(0, RECOVERY_CODE_LENGTH)
                .toUpperCase();
            // Format: XXXX-XXXX
            codes.push(`${code.slice(0, 4)}-${code.slice(4)}`);
        }
        return codes;
    }

    /**
     * Verify a TOTP code against the secret.
     * Accepts codes within ±TOTP_WINDOW time steps to account for clock drift.
     */
    public static verifyCode(secret: string, code: string): boolean {
        if (!code || code.length !== TOTP_DIGITS || !/^\d+$/.test(code)) {
            return false;
        }

        const currentStep = getCurrentTimeStep();

        // Check current time step and ±window
        for (let offset = -TOTP_WINDOW; offset <= TOTP_WINDOW; offset++) {
            const expectedCode = generateTOTPCode(secret, currentStep + offset);
            if (crypto.timingSafeEqual(
                Buffer.from(code),
                Buffer.from(expectedCode)
            )) {
                return true;
            }
        }

        return false;
    }

    /**
     * Verify a recovery code (one-time use).
     * Returns the updated list of remaining recovery codes if valid.
     */
    public static verifyRecoveryCode(
        code: string,
        remainingCodes: string[]
    ): { valid: boolean; updatedCodes: string[] } {
        const normalizedCode = code.toUpperCase().replace(/\s/g, '');
        const index = remainingCodes.findIndex(
            c => c.replace(/-/g, '') === normalizedCode.replace(/-/g, '')
        );

        if (index === -1) {
            return { valid: false, updatedCodes: remainingCodes };
        }

        // Remove the used code
        const updatedCodes = [...remainingCodes];
        updatedCodes.splice(index, 1);

        return { valid: true, updatedCodes };
    }

    /**
     * Check if a user account is locked due to too many failed attempts.
     */
    public static isLocked(record: TOTPUserRecord): boolean {
        if (!record.lockedUntil) return false;
        if (new Date() > record.lockedUntil) {
            record.lockedUntil = undefined;
            record.failedAttempts = 0;
            return false;
        }
        return true;
    }

    /**
     * Record a failed MFA attempt and potentially lock the account.
     */
    public static recordFailedAttempt(record: TOTPUserRecord): {
        locked: boolean;
        remainingAttempts: number;
        lockedUntil?: Date;
    } {
        record.failedAttempts++;

        if (record.failedAttempts >= MAX_FAILED_ATTEMPTS) {
            record.lockedUntil = new Date(Date.now() + LOCKOUT_DURATION_MS);
            return {
                locked: true,
                remainingAttempts: 0,
                lockedUntil: record.lockedUntil
            };
        }

        return {
            locked: false,
            remainingAttempts: MAX_FAILED_ATTEMPTS - record.failedAttempts
        };
    }

    /**
     * Record a successful MFA verification.
     */
    public static recordSuccessfulVerification(record: TOTPUserRecord): void {
        record.failedAttempts = 0;
        record.lockedUntil = undefined;
        record.lastUsedAt = new Date();
    }

    /**
     * Generate the current valid code (for testing purposes only).
     * NEVER expose this in production endpoints.
     */
    public static getCurrentCode(secret: string): string {
        return generateTOTPCode(secret, getCurrentTimeStep());
    }
}
