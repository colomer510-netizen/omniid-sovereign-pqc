/**
 * OmniID GDPR — Audit Event Types
 * 
 * Defines all auditable event types for the GDPR-compliant audit log.
 * Used by the AuditLogger to categorize and track data processing activities.
 * 
 * GDPR Articles: Art. 30 — Records of processing activities
 */

// ─── Event Categories ────────────────────────────────────────────────────────

export enum AuditEventType {
    // Identity lifecycle
    IDENTITY_ISSUED = 'IDENTITY_ISSUED',
    IDENTITY_VERIFIED = 'IDENTITY_VERIFIED',
    IDENTITY_REVOKED = 'IDENTITY_REVOKED',

    // Consent management
    CONSENT_GRANTED = 'CONSENT_GRANTED',
    CONSENT_REVOKED = 'CONSENT_REVOKED',
    CONSENT_UPDATED = 'CONSENT_UPDATED',

    // GDPR rights exercised
    DATA_ACCESSED = 'DATA_ACCESSED',
    DATA_EXPORTED = 'DATA_EXPORTED',
    DATA_ERASED = 'DATA_ERASED',
    DATA_RECTIFIED = 'DATA_RECTIFIED',
    ERASURE_REQUESTED = 'ERASURE_REQUESTED',
    ERASURE_CANCELLED = 'ERASURE_CANCELLED',
    ERASURE_COMPLETED = 'ERASURE_COMPLETED',

    // Authentication events
    LOGIN_SUCCESS = 'LOGIN_SUCCESS',
    LOGIN_FAILED = 'LOGIN_FAILED',
    LOGOUT = 'LOGOUT',
    MFA_ENROLLED = 'MFA_ENROLLED',
    MFA_VERIFIED = 'MFA_VERIFIED',
    MFA_FAILED = 'MFA_FAILED',
    SESSION_REFRESHED = 'SESSION_REFRESHED',
    SESSION_REVOKED = 'SESSION_REVOKED',
    ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
    ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED',

    // Admin operations
    ADMIN_ACCESS = 'ADMIN_ACCESS',
    USER_CREATED = 'USER_CREATED',
    USER_DELETED = 'USER_DELETED',
    ROLE_CHANGED = 'ROLE_CHANGED',
    POLICY_UPDATED = 'POLICY_UPDATED',

    // Security events
    BREACH_DETECTED = 'BREACH_DETECTED',
    IP_BLOCKED = 'IP_BLOCKED',
    DLP_ALERT = 'DLP_ALERT',
    DEFENSIVE_MODE_ACTIVATED = 'DEFENSIVE_MODE_ACTIVATED',
    DEFENSIVE_MODE_DEACTIVATED = 'DEFENSIVE_MODE_DEACTIVATED',

    // System events
    KEY_ROTATION = 'KEY_ROTATION',
    SYSTEM_STARTUP = 'SYSTEM_STARTUP',
    SYSTEM_SHUTDOWN = 'SYSTEM_SHUTDOWN',
    CONFIG_CHANGED = 'CONFIG_CHANGED'
}

// ─── CRUD Action Types ──────────────────────────────────────────────────────

export enum AuditAction {
    CREATE = 'CREATE',
    READ = 'READ',
    UPDATE = 'UPDATE',
    DELETE = 'DELETE',
    EXPORT = 'EXPORT',
    VERIFY = 'VERIFY',
    AUTHENTICATE = 'AUTHENTICATE',
    CONFIGURE = 'CONFIGURE'
}

// ─── Outcome Types ───────────────────────────────────────────────────────────

export enum AuditOutcome {
    SUCCESS = 'SUCCESS',
    FAILURE = 'FAILURE',
    DENIED = 'DENIED',
    ERROR = 'ERROR'
}

// ─── Audit Entry Structure ───────────────────────────────────────────────────

export interface AuditEntry {
    eventId: string;                   // UUID v4
    timestamp: string;                 // UTC ISO 8601
    eventType: AuditEventType;
    action: AuditAction;
    actorId: string;                   // DID of the user, or 'SYSTEM'
    actorRole: string;                 // CITIZEN | OPERATOR | ADMIN | DPO | SYSTEM
    targetResource: string;            // Resource affected (e.g., "identity:did:omni:X123...")
    details: Record<string, any>;      // Additional metadata (NO raw PII)
    ipAddressHash: string;             // SHA-256 of IP address
    userAgent?: string;                // Truncated user agent
    requestId?: string;                // Correlation ID
    outcome: AuditOutcome;
    integrityHash: string;             // SHA-256 chain hash (tamper-evident)
    gdprLegalBasis?: string;           // Legal basis for the processing
}

// ─── GDPR Processing Purposes ────────────────────────────────────────────────

export enum ProcessingPurpose {
    IDENTITY_ISSUANCE = 'identity_issuance',
    BIOMETRIC_STORAGE = 'biometric_storage',
    VERIFICATION = 'verification',
    CONSENT_MANAGEMENT = 'consent_management',
    SECURITY_MONITORING = 'security_monitoring',
    GDPR_COMPLIANCE = 'gdpr_compliance',
    ANALYTICS = 'analytics',
    MARKETING = 'marketing'
}

export enum LegalBasis {
    CONSENT = 'consent',                        // Art. 6(1)(a)
    CONTRACT = 'contract',                      // Art. 6(1)(b)
    LEGAL_OBLIGATION = 'legal_obligation',       // Art. 6(1)(c)
    VITAL_INTEREST = 'vital_interest',           // Art. 6(1)(d)
    PUBLIC_INTEREST = 'public_interest',          // Art. 6(1)(e)
    LEGITIMATE_INTEREST = 'legitimate_interest'   // Art. 6(1)(f)
}
