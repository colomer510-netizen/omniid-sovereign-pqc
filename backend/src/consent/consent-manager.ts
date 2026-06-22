/**
 * OmniID GDPR — Consent Manager Module
 * 
 * Manages granular, revocable user consent with full audit trail.
 * Each consent grant is individually trackable and revocable.
 * 
 * GDPR Articles: Art. 6 (lawfulness), Art. 7 (conditions for consent)
 */

import * as crypto from 'crypto';

// ─── Types ───────────────────────────────────────────────────────────────────

export enum ConsentPurpose {
    IDENTITY_ISSUANCE = 'identity_issuance',
    BIOMETRIC_STORAGE = 'biometric_storage',
    ANALYTICS = 'analytics',
    MARKETING = 'marketing',
    FUNCTIONAL = 'functional'
}

export enum ConsentLegalBasis {
    CONSENT = 'consent',
    CONTRACT = 'contract',
    LEGAL_OBLIGATION = 'legal_obligation',
    LEGITIMATE_INTEREST = 'legitimate_interest'
}

export interface ConsentRecord {
    consentId: string;
    userId: string;
    purpose: ConsentPurpose;
    legalBasis: ConsentLegalBasis;
    granted: boolean;
    grantedAt: Date;
    revokedAt?: Date;
    policyVersion: string;
    ipAddressHash: string;
    userAgent: string;
}

export interface ConsentStatus {
    purpose: ConsentPurpose;
    granted: boolean;
    grantedAt?: Date;
    policyVersion?: string;
    description: string;
    required: boolean;
}

// ─── Purpose Descriptions ────────────────────────────────────────────────────

const PURPOSE_DESCRIPTIONS: Record<ConsentPurpose, { description: string; required: boolean }> = {
    [ConsentPurpose.IDENTITY_ISSUANCE]: {
        description: 'Procesamiento de datos personales para la emisión y verificación de credenciales de identidad digital.',
        required: true
    },
    [ConsentPurpose.BIOMETRIC_STORAGE]: {
        description: 'Almacenamiento cifrado del compromiso criptográfico de datos biométricos (hash Fuzzy Commitment).',
        required: true
    },
    [ConsentPurpose.ANALYTICS]: {
        description: 'Recopilación anónima de estadísticas de uso para mejorar el servicio.',
        required: false
    },
    [ConsentPurpose.MARKETING]: {
        description: 'Envío de comunicaciones sobre novedades y actualizaciones del servicio.',
        required: false
    },
    [ConsentPurpose.FUNCTIONAL]: {
        description: 'Almacenamiento de preferencias de usuario (idioma, tema) para personalización.',
        required: false
    }
};

// ─── Consent Store ───────────────────────────────────────────────────────────

const consentStore: ConsentRecord[] = [];

// ─── Helper ──────────────────────────────────────────────────────────────────

function hashIP(ip: string): string {
    return crypto.createHash('sha256')
        .update(ip + (process.env.OMNIID_IP_SALT || 'omniid-consent-salt'))
        .digest('hex')
        .substring(0, 16);
}

// ─── Consent Manager ─────────────────────────────────────────────────────────

export class ConsentManager {
    /**
     * Grant consent for one or more purposes.
     */
    public static grantConsent(params: {
        userId: string;
        purposes: ConsentPurpose[];
        policyVersion: string;
        ipAddress: string;
        userAgent: string;
    }): ConsentRecord[] {
        const records: ConsentRecord[] = [];

        for (const purpose of params.purposes) {
            // Revoke any existing active consent for this purpose (to create fresh record)
            const existing = consentStore.find(
                c => c.userId === params.userId && c.purpose === purpose && c.granted && !c.revokedAt
            );
            if (existing) {
                existing.revokedAt = new Date();
                existing.granted = false;
            }

            const record: ConsentRecord = {
                consentId: crypto.randomUUID(),
                userId: params.userId,
                purpose,
                legalBasis: PURPOSE_DESCRIPTIONS[purpose].required
                    ? ConsentLegalBasis.CONTRACT
                    : ConsentLegalBasis.CONSENT,
                granted: true,
                grantedAt: new Date(),
                policyVersion: params.policyVersion,
                ipAddressHash: hashIP(params.ipAddress),
                userAgent: params.userAgent.substring(0, 200)
            };

            consentStore.push(record);
            records.push(record);
        }

        return records;
    }

    /**
     * Revoke consent for a specific purpose.
     */
    public static revokeConsent(userId: string, purpose: ConsentPurpose): boolean {
        const record = consentStore.find(
            c => c.userId === userId && c.purpose === purpose && c.granted && !c.revokedAt
        );

        if (!record) return false;

        // Check if the purpose is required (cannot revoke)
        if (PURPOSE_DESCRIPTIONS[purpose].required) {
            return false; // Required consents cannot be individually revoked
        }

        record.revokedAt = new Date();
        record.granted = false;
        return true;
    }

    /**
     * Check if a user has active consent for a specific purpose.
     */
    public static hasConsent(userId: string, purpose: ConsentPurpose): boolean {
        return consentStore.some(
            c => c.userId === userId && c.purpose === purpose && c.granted && !c.revokedAt
        );
    }

    /**
     * Get the current consent status for all purposes for a user.
     */
    public static getConsentStatus(userId: string): ConsentStatus[] {
        return Object.values(ConsentPurpose).map(purpose => {
            const activeConsent = consentStore.find(
                c => c.userId === userId && c.purpose === purpose && c.granted && !c.revokedAt
            );

            return {
                purpose,
                granted: !!activeConsent,
                grantedAt: activeConsent?.grantedAt,
                policyVersion: activeConsent?.policyVersion,
                description: PURPOSE_DESCRIPTIONS[purpose].description,
                required: PURPOSE_DESCRIPTIONS[purpose].required
            };
        });
    }

    /**
     * Get the full consent history for a user (for GDPR transparency).
     */
    public static getConsentHistory(userId: string): ConsentRecord[] {
        return consentStore
            .filter(c => c.userId === userId)
            .sort((a, b) => b.grantedAt.getTime() - a.grantedAt.getTime());
    }

    /**
     * Delete all consent records for a user (for right to erasure).
     */
    public static deleteUserConsents(userId: string): number {
        let deleted = 0;
        for (let i = consentStore.length - 1; i >= 0; i--) {
            if (consentStore[i].userId === userId) {
                consentStore.splice(i, 1);
                deleted++;
            }
        }
        return deleted;
    }

    /**
     * Get all available consent purposes with descriptions.
     */
    public static getAvailablePurposes(): Array<{
        purpose: ConsentPurpose;
        description: string;
        required: boolean;
    }> {
        return Object.entries(PURPOSE_DESCRIPTIONS).map(([purpose, info]) => ({
            purpose: purpose as ConsentPurpose,
            description: info.description,
            required: info.required
        }));
    }
}
