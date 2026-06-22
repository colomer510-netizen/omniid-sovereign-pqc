/**
 * OmniID GDPR — Consent API Routes
 * 
 * Endpoints for managing user consent: granting, revoking, viewing status,
 * and retrieving consent history.
 * 
 * GDPR Articles: Art. 7 — Conditions for consent
 */

import { Router, Response } from 'express';
import { ConsentManager, ConsentPurpose } from './consent-manager';
import { requireAuth, AuthenticatedRequest } from '../auth/middleware';
import { AuditLogger } from '../audit/audit-logger';
import { AuditEventType, AuditAction, AuditOutcome } from '../audit/audit-types';

export const consentRouter = Router();

/**
 * GET /api/v1/consent/purposes
 * List all available consent purposes. Public endpoint.
 */
consentRouter.get('/purposes', (req, res: Response) => {
    res.json({
        success: true,
        purposes: ConsentManager.getAvailablePurposes(),
        currentPolicyVersion: process.env.PRIVACY_POLICY_VERSION || '1.0'
    });
});

/**
 * GET /api/v1/consent/status
 * Get current consent status for the authenticated user.
 */
consentRouter.get('/status',
    requireAuth,
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required.' });
        }

        const status = ConsentManager.getConsentStatus(req.user.did);
        res.json({
            success: true,
            userId: req.user.did,
            consents: status
        });
    }
);

/**
 * POST /api/v1/consent/grant
 * Grant consent for one or more purposes.
 */
consentRouter.post('/grant',
    requireAuth,
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required.' });
        }

        const { purposes, policyVersion } = req.body;

        if (!purposes || !Array.isArray(purposes) || purposes.length === 0) {
            return res.status(400).json({
                success: false,
                error: 'At least one consent purpose must be specified.'
            });
        }

        // Validate purposes
        const validPurposes = Object.values(ConsentPurpose);
        for (const p of purposes) {
            if (!validPurposes.includes(p)) {
                return res.status(400).json({
                    success: false,
                    error: `Invalid consent purpose: ${p}. Valid purposes: ${validPurposes.join(', ')}`
                });
            }
        }

        const records = ConsentManager.grantConsent({
            userId: req.user.did,
            purposes,
            policyVersion: policyVersion || process.env.PRIVACY_POLICY_VERSION || '1.0',
            ipAddress: req.ip || 'unknown',
            userAgent: req.headers['user-agent'] || 'unknown'
        });

        // Audit log
        AuditLogger.log({
            eventType: AuditEventType.CONSENT_GRANTED,
            action: AuditAction.CREATE,
            actorId: req.user.did,
            actorRole: req.user.role,
            targetResource: `consent:${req.user.did}`,
            details: { purposes, policyVersion },
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            requestId: (req as any).requestId,
            outcome: AuditOutcome.SUCCESS,
            gdprLegalBasis: 'consent'
        });

        res.status(201).json({
            success: true,
            message: 'Consent granted successfully.',
            records: records.map(r => ({
                consentId: r.consentId,
                purpose: r.purpose,
                grantedAt: r.grantedAt
            }))
        });
    }
);

/**
 * DELETE /api/v1/consent/revoke/:purpose
 * Revoke consent for a specific purpose.
 */
consentRouter.delete('/revoke/:purpose',
    requireAuth,
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required.' });
        }

        const purpose = req.params.purpose as ConsentPurpose;

        if (!Object.values(ConsentPurpose).includes(purpose)) {
            return res.status(400).json({
                success: false,
                error: `Invalid consent purpose: ${purpose}`
            });
        }

        const revoked = ConsentManager.revokeConsent(req.user.did, purpose);

        if (!revoked) {
            return res.status(400).json({
                success: false,
                error: 'Consent could not be revoked. It may be a required consent or already inactive.'
            });
        }

        // Audit log
        AuditLogger.log({
            eventType: AuditEventType.CONSENT_REVOKED,
            action: AuditAction.DELETE,
            actorId: req.user.did,
            actorRole: req.user.role,
            targetResource: `consent:${req.user.did}:${purpose}`,
            details: { purpose },
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            requestId: (req as any).requestId,
            outcome: AuditOutcome.SUCCESS,
            gdprLegalBasis: 'consent'
        });

        res.json({
            success: true,
            message: `Consent for '${purpose}' has been revoked.`
        });
    }
);

/**
 * GET /api/v1/consent/history
 * Get full consent history for the authenticated user.
 */
consentRouter.get('/history',
    requireAuth,
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required.' });
        }

        const history = ConsentManager.getConsentHistory(req.user.did);
        res.json({
            success: true,
            userId: req.user.did,
            history
        });
    }
);
