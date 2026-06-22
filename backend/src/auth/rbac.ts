/**
 * OmniID GDPR — Role-Based Access Control (RBAC) Module
 * 
 * Defines roles, permissions, and MFA requirements for all system actors.
 * Enforces the principle of least privilege for GDPR compliance.
 * 
 * GDPR Articles: Art. 25 — Data protection by design
 *                Art. 32 — Security of processing
 */

// ─── Roles ───────────────────────────────────────────────────────────────────

export enum Role {
    CITIZEN = 'CITIZEN',       // Data subject / holder
    OPERATOR = 'OPERATOR',     // Government issuer / verifier
    ADMIN = 'ADMIN',           // System administrator
    DPO = 'DPO'                // Data Protection Officer
}

// ─── Permissions ─────────────────────────────────────────────────────────────

export enum Permission {
    // Identity operations
    IDENTITY_ISSUE = 'identity:issue',
    IDENTITY_VERIFY = 'identity:verify',
    IDENTITY_REVOKE = 'identity:revoke',

    // Own data operations (GDPR rights)
    OWN_DATA_VIEW = 'own_data:view',
    OWN_DATA_EXPORT = 'own_data:export',
    OWN_DATA_ERASE = 'own_data:erase',
    OWN_DATA_RECTIFY = 'own_data:rectify',

    // Consent management
    CONSENT_MANAGE = 'consent:manage',
    CONSENT_VIEW_ALL = 'consent:view_all',

    // Admin operations
    ADMIN_USERS = 'admin:users',
    ADMIN_AUDIT_LOGS = 'admin:audit_logs',
    ADMIN_POLICIES = 'admin:policies',
    ADMIN_BREACH_REPORT = 'admin:breach_report',
    ADMIN_DEFENSIVE_MODE = 'admin:defensive_mode',

    // DPO operations
    DPO_APPROVE_ERASURE = 'dpo:approve_erasure',
    DPO_COMPLIANCE_REPORT = 'dpo:compliance_report',
    DPO_BREACH_NOTIFY = 'dpo:breach_notify'
}

// ─── MFA Requirements ────────────────────────────────────────────────────────

export enum MFARequirement {
    NONE = 'none',
    TOTP = 'totp',
    WEBAUTHN = 'webauthn',
    TOTP_AND_WEBAUTHN = 'totp_and_webauthn'
}

// ─── Role Definitions ────────────────────────────────────────────────────────

interface RoleDefinition {
    permissions: Permission[];
    mfaRequirement: MFARequirement;
    description: string;
    maxSessionDurationHours: number;
}

const ROLE_DEFINITIONS: Record<Role, RoleDefinition> = {
    [Role.CITIZEN]: {
        permissions: [
            Permission.OWN_DATA_VIEW,
            Permission.OWN_DATA_EXPORT,
            Permission.OWN_DATA_ERASE,
            Permission.OWN_DATA_RECTIFY,
            Permission.CONSENT_MANAGE
        ],
        mfaRequirement: MFARequirement.TOTP,
        description: 'Data subject — can view, export, erase, and rectify their own data',
        maxSessionDurationHours: 24
    },

    [Role.OPERATOR]: {
        permissions: [
            Permission.IDENTITY_ISSUE,
            Permission.IDENTITY_VERIFY,
            Permission.OWN_DATA_VIEW,
            Permission.OWN_DATA_EXPORT,
            Permission.CONSENT_MANAGE
        ],
        mfaRequirement: MFARequirement.WEBAUTHN,
        description: 'Government operator — can issue and verify credentials',
        maxSessionDurationHours: 8
    },

    [Role.ADMIN]: {
        permissions: [
            Permission.IDENTITY_ISSUE,
            Permission.IDENTITY_VERIFY,
            Permission.IDENTITY_REVOKE,
            Permission.OWN_DATA_VIEW,
            Permission.OWN_DATA_EXPORT,
            Permission.CONSENT_MANAGE,
            Permission.CONSENT_VIEW_ALL,
            Permission.ADMIN_USERS,
            Permission.ADMIN_AUDIT_LOGS,
            Permission.ADMIN_POLICIES,
            Permission.ADMIN_BREACH_REPORT,
            Permission.ADMIN_DEFENSIVE_MODE
        ],
        mfaRequirement: MFARequirement.TOTP_AND_WEBAUTHN,
        description: 'System administrator — full system access except DPO-specific functions',
        maxSessionDurationHours: 4
    },

    [Role.DPO]: {
        permissions: [
            Permission.OWN_DATA_VIEW,
            Permission.CONSENT_VIEW_ALL,
            Permission.ADMIN_AUDIT_LOGS,
            Permission.ADMIN_BREACH_REPORT,
            Permission.DPO_APPROVE_ERASURE,
            Permission.DPO_COMPLIANCE_REPORT,
            Permission.DPO_BREACH_NOTIFY
        ],
        mfaRequirement: MFARequirement.TOTP_AND_WEBAUTHN,
        description: 'Data Protection Officer — oversees GDPR compliance and breach notifications',
        maxSessionDurationHours: 4
    }
};

// ─── RBAC Engine ─────────────────────────────────────────────────────────────

export class RBACEngine {
    /**
     * Check if a role has a specific permission.
     */
    public static hasPermission(role: Role | string, permission: Permission): boolean {
        const roleDef = ROLE_DEFINITIONS[role as Role];
        if (!roleDef) return false;
        return roleDef.permissions.includes(permission);
    }

    /**
     * Get all permissions for a role.
     */
    public static getPermissions(role: Role | string): Permission[] {
        const roleDef = ROLE_DEFINITIONS[role as Role];
        if (!roleDef) return [];
        return [...roleDef.permissions];
    }

    /**
     * Get the MFA requirement for a role.
     */
    public static getMFARequirement(role: Role | string): MFARequirement {
        const roleDef = ROLE_DEFINITIONS[role as Role];
        if (!roleDef) return MFARequirement.TOTP_AND_WEBAUTHN; // Default: strictest
        return roleDef.mfaRequirement;
    }

    /**
     * Get the maximum session duration for a role.
     */
    public static getMaxSessionDuration(role: Role | string): number {
        const roleDef = ROLE_DEFINITIONS[role as Role];
        if (!roleDef) return 1; // Default: 1 hour
        return roleDef.maxSessionDurationHours;
    }

    /**
     * Get role description.
     */
    public static getRoleDescription(role: Role | string): string {
        const roleDef = ROLE_DEFINITIONS[role as Role];
        if (!roleDef) return 'Unknown role';
        return roleDef.description;
    }

    /**
     * Get all defined roles and their info.
     */
    public static getAllRoles(): Array<{
        role: Role;
        description: string;
        permissionCount: number;
        mfaRequirement: string;
    }> {
        return Object.entries(ROLE_DEFINITIONS).map(([role, def]) => ({
            role: role as Role,
            description: def.description,
            permissionCount: def.permissions.length,
            mfaRequirement: def.mfaRequirement
        }));
    }

    /**
     * Validate that a role string is a valid Role enum value.
     */
    public static isValidRole(role: string): role is Role {
        return Object.values(Role).includes(role as Role);
    }
}
