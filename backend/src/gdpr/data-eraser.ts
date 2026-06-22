/**
 * OmniID GDPR — Data Eraser Module
 * 
 * Implements the Right to Erasure (Art. 17 GDPR) with confirmation flow,
 * grace period, and selective anonymization of audit records.
 * 
 * GDPR Articles: Art. 17 — Right to erasure ('right to be forgotten')
 */

import * as crypto from 'crypto';
import { AuditLogger } from '../audit/audit-logger';
import { AuditEventType, AuditAction, AuditOutcome } from '../audit/audit-types';
import { ConsentManager } from '../consent/consent-manager';
import { SessionManager } from '../auth/session-manager';

// ─── Types ───────────────────────────────────────────────────────────────────

export enum ErasureStatus {
    PENDING_CONFIRMATION = 'PENDING_CONFIRMATION',
    CONFIRMED = 'CONFIRMED',
    IN_GRACE_PERIOD = 'IN_GRACE_PERIOD',
    PROCESSING = 'PROCESSING',
    COMPLETED = 'COMPLETED',
    CANCELLED = 'CANCELLED',
    FAILED = 'FAILED'
}

export interface ErasureRequest {
    requestId: string;
    userId: string;
    status: ErasureStatus;
    requestedAt: Date;
    confirmationToken: string;
    confirmedAt?: Date;
    gracePeriodEndsAt?: Date;
    completedAt?: Date;
    cancelledAt?: Date;
    reason?: string;
    deletionReport?: DeletionReport;
}

export interface DeletionReport {
    piiDeleted: boolean;
    credentialsRevoked: number;
    biometricDeleted: boolean;
    auditEntriesAnonymized: number;
    sessionsRevoked: number;
    consentsDeleted: number;
    completedAt: string;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const CONFIRMATION_TOKEN_TTL_HOURS = 24;
const GRACE_PERIOD_DAYS = 7;

// ─── Erasure Request Store ───────────────────────────────────────────────────

const erasureRequests = new Map<string, ErasureRequest>();

// ─── Data Eraser ─────────────────────────────────────────────────────────────

export class DataEraser {
    /**
     * Create a new erasure request. Generates a confirmation token
     * that must be verified (e.g., via email) within 24 hours.
     */
    public static createRequest(userId: string, reason?: string): ErasureRequest {
        // Check for existing pending request
        for (const req of erasureRequests.values()) {
            if (req.userId === userId && 
                [ErasureStatus.PENDING_CONFIRMATION, ErasureStatus.CONFIRMED, ErasureStatus.IN_GRACE_PERIOD].includes(req.status)) {
                throw new Error('An erasure request is already pending for this user.');
            }
        }

        const request: ErasureRequest = {
            requestId: crypto.randomUUID(),
            userId,
            status: ErasureStatus.PENDING_CONFIRMATION,
            requestedAt: new Date(),
            confirmationToken: crypto.randomBytes(32).toString('hex'),
            reason
        };

        erasureRequests.set(request.requestId, request);

        // Audit log
        AuditLogger.log({
            eventType: AuditEventType.ERASURE_REQUESTED,
            action: AuditAction.CREATE,
            actorId: userId,
            actorRole: 'CITIZEN',
            targetResource: `erasure:${request.requestId}`,
            details: { reason: reason || 'User initiated', status: request.status },
            outcome: AuditOutcome.SUCCESS,
            gdprLegalBasis: 'consent'
        });

        return request;
    }

    /**
     * Confirm an erasure request using the confirmation token.
     * Starts the 7-day grace period.
     */
    public static confirmRequest(requestId: string, token: string): ErasureRequest | null {
        const request = erasureRequests.get(requestId);
        if (!request) return null;

        if (request.status !== ErasureStatus.PENDING_CONFIRMATION) {
            return null;
        }

        // Check token expiry
        const tokenAge = Date.now() - request.requestedAt.getTime();
        if (tokenAge > CONFIRMATION_TOKEN_TTL_HOURS * 60 * 60 * 1000) {
            request.status = ErasureStatus.CANCELLED;
            request.cancelledAt = new Date();
            request.reason = 'Confirmation token expired (24h timeout)';
            return null;
        }

        // Verify token
        if (request.confirmationToken !== token) {
            return null;
        }

        // Move to grace period
        request.status = ErasureStatus.IN_GRACE_PERIOD;
        request.confirmedAt = new Date();
        request.gracePeriodEndsAt = new Date(Date.now() + GRACE_PERIOD_DAYS * 24 * 60 * 60 * 1000);

        AuditLogger.log({
            eventType: AuditEventType.ERASURE_REQUESTED,
            action: AuditAction.UPDATE,
            actorId: request.userId,
            actorRole: 'CITIZEN',
            targetResource: `erasure:${requestId}`,
            details: {
                status: 'IN_GRACE_PERIOD',
                gracePeriodEndsAt: request.gracePeriodEndsAt.toISOString()
            },
            outcome: AuditOutcome.SUCCESS,
            gdprLegalBasis: 'consent'
        });

        return request;
    }

    /**
     * Cancel an erasure request during the grace period.
     */
    public static cancelRequest(requestId: string, userId: string): boolean {
        const request = erasureRequests.get(requestId);
        if (!request) return false;

        if (request.userId !== userId) return false;

        if (![ErasureStatus.PENDING_CONFIRMATION, ErasureStatus.CONFIRMED, ErasureStatus.IN_GRACE_PERIOD].includes(request.status)) {
            return false;
        }

        request.status = ErasureStatus.CANCELLED;
        request.cancelledAt = new Date();
        request.reason = 'Cancelled by user during grace period';

        AuditLogger.log({
            eventType: AuditEventType.ERASURE_CANCELLED,
            action: AuditAction.UPDATE,
            actorId: userId,
            actorRole: 'CITIZEN',
            targetResource: `erasure:${requestId}`,
            details: { status: 'CANCELLED' },
            outcome: AuditOutcome.SUCCESS,
            gdprLegalBasis: 'consent'
        });

        return true;
    }

    /**
     * Execute the erasure after the grace period has elapsed.
     * This is the critical deletion operation.
     * 
     * @param deleteIdentityCallback - Function to delete PII from the identity store
     */
    public static executeErasure(
        requestId: string,
        deleteIdentityCallback: (userId: string) => {
            piiDeleted: boolean;
            credentialsRevoked: number;
            biometricDeleted: boolean;
        }
    ): DeletionReport | null {
        const request = erasureRequests.get(requestId);
        if (!request) return null;

        if (request.status !== ErasureStatus.IN_GRACE_PERIOD) return null;

        // Check that grace period has actually elapsed
        if (request.gracePeriodEndsAt && new Date() < request.gracePeriodEndsAt) {
            return null; // Grace period hasn't ended yet
        }

        request.status = ErasureStatus.PROCESSING;

        try {
            // Step 1: Delete PII from identity store
            const identityResult = deleteIdentityCallback(request.userId);

            // Step 2: Revoke all sessions
            const sessionsRevoked = SessionManager.revokeAllSessions(request.userId);

            // Step 3: Delete consent records
            const consentsDeleted = ConsentManager.deleteUserConsents(request.userId);

            // Step 4: Anonymize audit entries (don't delete — legal requirement)
            const auditEntriesAnonymized = AuditLogger.anonymizeUser(request.userId);

            // Build report
            const report: DeletionReport = {
                piiDeleted: identityResult.piiDeleted,
                credentialsRevoked: identityResult.credentialsRevoked,
                biometricDeleted: identityResult.biometricDeleted,
                auditEntriesAnonymized,
                sessionsRevoked,
                consentsDeleted,
                completedAt: new Date().toISOString()
            };

            request.status = ErasureStatus.COMPLETED;
            request.completedAt = new Date();
            request.deletionReport = report;

            // Final audit entry (with anonymized user ID already)
            AuditLogger.log({
                eventType: AuditEventType.ERASURE_COMPLETED,
                action: AuditAction.DELETE,
                actorId: 'SYSTEM',
                actorRole: 'SYSTEM',
                targetResource: `erasure:${requestId}`,
                details: {
                    report,
                    gdprArticle: 'Art. 17 — Right to erasure executed'
                },
                outcome: AuditOutcome.SUCCESS,
                gdprLegalBasis: 'consent'
            });

            return report;
        } catch (error: any) {
            request.status = ErasureStatus.FAILED;
            request.reason = `Erasure failed: ${error.message}`;

            AuditLogger.log({
                eventType: AuditEventType.ERASURE_COMPLETED,
                action: AuditAction.DELETE,
                actorId: 'SYSTEM',
                actorRole: 'SYSTEM',
                targetResource: `erasure:${requestId}`,
                details: { error: error.message },
                outcome: AuditOutcome.ERROR,
                gdprLegalBasis: 'consent'
            });

            return null;
        }
    }

    /**
     * Get the status of an erasure request.
     */
    public static getRequestStatus(requestId: string): ErasureRequest | null {
        const request = erasureRequests.get(requestId);
        if (!request) return null;

        // Return without the confirmation token
        return {
            ...request,
            confirmationToken: '[HIDDEN]'
        };
    }

    /**
     * Get all erasure requests for a user.
     */
    public static getUserRequests(userId: string): ErasureRequest[] {
        const userRequests: ErasureRequest[] = [];
        for (const request of erasureRequests.values()) {
            if (request.userId === userId) {
                userRequests.push({
                    ...request,
                    confirmationToken: '[HIDDEN]'
                });
            }
        }
        return userRequests.sort((a, b) => b.requestedAt.getTime() - a.requestedAt.getTime());
    }

    /**
     * Process all matured erasure requests.
     * Should be called periodically (e.g., via cron or scheduler).
     */
    public static processMatureRequests(
        deleteIdentityCallback: (userId: string) => {
            piiDeleted: boolean;
            credentialsRevoked: number;
            biometricDeleted: boolean;
        }
    ): number {
        let processed = 0;
        const now = new Date();

        for (const request of erasureRequests.values()) {
            if (request.status === ErasureStatus.IN_GRACE_PERIOD &&
                request.gracePeriodEndsAt &&
                now >= request.gracePeriodEndsAt) {
                
                const result = DataEraser.executeErasure(request.requestId, deleteIdentityCallback);
                if (result) processed++;
            }
        }

        return processed;
    }
}
