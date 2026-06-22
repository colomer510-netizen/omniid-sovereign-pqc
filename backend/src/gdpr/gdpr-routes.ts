/**
 * OmniID GDPR — GDPR Rights API Routes
 * 
 * Endpoints for exercising GDPR data subject rights:
 * - Art. 15: Right of access
 * - Art. 16: Right to rectification
 * - Art. 17: Right to erasure
 * - Art. 20: Right to data portability
 * 
 * All endpoints require authentication + MFA.
 */

import { Router, Response } from 'express';
import { requireAuth, requirePermission, AuthenticatedRequest } from '../auth/middleware';
import { Permission } from '../auth/rbac';
import { DataExporter } from './data-exporter';
import { DataEraser, ErasureStatus } from './data-eraser';
import { ConsentManager } from '../consent/consent-manager';
import { AuditLogger } from '../audit/audit-logger';
import { AuditEventType, AuditAction, AuditOutcome } from '../audit/audit-types';

export const gdprRouter = Router();

// All GDPR endpoints require authentication
gdprRouter.use(requireAuth);

/**
 * GET /api/v1/gdpr/my-data
 * Download all personal data (Art. 15 + Art. 20).
 */
gdprRouter.get('/my-data',
    requirePermission(Permission.OWN_DATA_VIEW),
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required.' });
        }

        // Note: In production, the personal data would be fetched from the database
        // and decrypted. This is a structural implementation.
        const exportData = DataExporter.generateExport({
            userId: req.user.did,
            personalData: {
                // These would be decrypted from the DB in production
                fullName: '[Stored encrypted — decrypted on request]',
                dob: '[Stored encrypted — decrypted on request]',
                region: '[Stored encrypted — decrypted on request]'
            },
            credentials: [] // Would be populated from identity store
        });

        AuditLogger.log({
            eventType: AuditEventType.DATA_ACCESSED,
            action: AuditAction.READ,
            actorId: req.user.did,
            actorRole: req.user.role,
            targetResource: `personal-data:${req.user.did}`,
            details: { action: 'GDPR Art. 15 — Data Access' },
            ipAddress: req.ip,
            requestId: (req as any).requestId,
            outcome: AuditOutcome.SUCCESS,
            gdprLegalBasis: 'consent'
        });

        res.json({
            success: true,
            data: exportData
        });
    }
);

/**
 * POST /api/v1/gdpr/export
 * Request data export in portable format (Art. 20).
 */
gdprRouter.post('/export',
    requirePermission(Permission.OWN_DATA_EXPORT),
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required.' });
        }

        const format = req.body.format || 'json';

        const exportData = DataExporter.generateExport({
            userId: req.user.did,
            personalData: {
                fullName: '[Stored encrypted — decrypted on request]',
                dob: '[Stored encrypted — decrypted on request]',
                region: '[Stored encrypted — decrypted on request]'
            },
            credentials: [],
            format
        });

        AuditLogger.log({
            eventType: AuditEventType.DATA_EXPORTED,
            action: AuditAction.EXPORT,
            actorId: req.user.did,
            actorRole: req.user.role,
            targetResource: `personal-data:${req.user.did}`,
            details: { format, action: 'GDPR Art. 20 — Data Portability' },
            ipAddress: req.ip,
            requestId: (req as any).requestId,
            outcome: AuditOutcome.SUCCESS,
            gdprLegalBasis: 'consent'
        });

        if (format === 'text') {
            const textReport = DataExporter.generateTextReport(exportData);
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.setHeader('Content-Disposition', `attachment; filename="omniid-data-export-${Date.now()}.txt"`);
            return res.send(textReport);
        }

        res.setHeader('Content-Disposition', `attachment; filename="omniid-data-export-${Date.now()}.json"`);
        res.json({
            success: true,
            export: exportData
        });
    }
);

/**
 * POST /api/v1/gdpr/erase
 * Request data erasure — Right to be Forgotten (Art. 17).
 */
gdprRouter.post('/erase',
    requirePermission(Permission.OWN_DATA_ERASE),
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required.' });
        }

        try {
            const request = DataEraser.createRequest(req.user.did, req.body.reason);

            res.status(202).json({
                success: true,
                message: 'Erasure request created. A confirmation token has been generated.',
                requestId: request.requestId,
                confirmationToken: request.confirmationToken, // In production: sent via email
                confirmationDeadline: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
                instructions: 'Confirm the request within 24 hours to start the 7-day grace period.',
                note: 'You can cancel the erasure during the grace period.'
            });
        } catch (error: any) {
            res.status(409).json({
                success: false,
                error: error.message
            });
        }
    }
);

/**
 * POST /api/v1/gdpr/erase/:requestId/confirm
 * Confirm an erasure request with the confirmation token.
 */
gdprRouter.post('/erase/:requestId/confirm',
    (req: AuthenticatedRequest, res: Response) => {
        const { requestId } = req.params;
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({
                success: false,
                error: 'Confirmation token is required.'
            });
        }

        const result = DataEraser.confirmRequest(requestId, token);

        if (!result) {
            return res.status(400).json({
                success: false,
                error: 'Invalid or expired confirmation token.'
            });
        }

        res.json({
            success: true,
            message: 'Erasure request confirmed. Grace period has started.',
            requestId: result.requestId,
            status: result.status,
            gracePeriodEndsAt: result.gracePeriodEndsAt?.toISOString(),
            cancelDeadline: result.gracePeriodEndsAt?.toISOString(),
            note: 'You can cancel this request before the grace period ends.'
        });
    }
);

/**
 * POST /api/v1/gdpr/erase/:requestId/cancel
 * Cancel an erasure request during the grace period.
 */
gdprRouter.post('/erase/:requestId/cancel',
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required.' });
        }

        const cancelled = DataEraser.cancelRequest(req.params.requestId, req.user.did);

        if (!cancelled) {
            return res.status(400).json({
                success: false,
                error: 'Cannot cancel this request. It may have already been processed or does not belong to you.'
            });
        }

        res.json({
            success: true,
            message: 'Erasure request has been cancelled. Your data remains intact.'
        });
    }
);

/**
 * GET /api/v1/gdpr/erase/:requestId/status
 * Check the status of an erasure request.
 */
gdprRouter.get('/erase/:requestId/status',
    (req: AuthenticatedRequest, res: Response) => {
        const request = DataEraser.getRequestStatus(req.params.requestId);

        if (!request) {
            return res.status(404).json({
                success: false,
                error: 'Erasure request not found.'
            });
        }

        res.json({
            success: true,
            request
        });
    }
);

/**
 * POST /api/v1/gdpr/rectify
 * Request data rectification (Art. 16).
 */
gdprRouter.post('/rectify',
    requirePermission(Permission.OWN_DATA_RECTIFY),
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required.' });
        }

        const { field, newValue, reason } = req.body;

        if (!field || !newValue || !reason) {
            return res.status(400).json({
                success: false,
                error: 'Field, new value, and reason are required for rectification.'
            });
        }

        const allowedFields = ['fullName', 'dob', 'region'];
        if (!allowedFields.includes(field)) {
            return res.status(400).json({
                success: false,
                error: `Field '${field}' cannot be rectified. Allowed: ${allowedFields.join(', ')}`
            });
        }

        // In production: queue the rectification for admin/DPO review
        AuditLogger.log({
            eventType: AuditEventType.DATA_RECTIFIED,
            action: AuditAction.UPDATE,
            actorId: req.user.did,
            actorRole: req.user.role,
            targetResource: `personal-data:${req.user.did}:${field}`,
            details: { field, reason, action: 'GDPR Art. 16 — Rectification request' },
            ipAddress: req.ip,
            requestId: (req as any).requestId,
            outcome: AuditOutcome.SUCCESS,
            gdprLegalBasis: 'consent'
        });

        res.status(202).json({
            success: true,
            message: `Rectification request for '${field}' has been submitted for review.`,
            field,
            note: 'A DPO will review and process your request within 30 days (Art. 12(3) GDPR).'
        });
    }
);

/**
 * GET /api/v1/gdpr/consent-history
 * View the complete consent history (Art. 7(1) — proof of consent).
 */
gdprRouter.get('/consent-history',
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required.' });
        }

        const history = ConsentManager.getConsentHistory(req.user.did);
        res.json({
            success: true,
            userId: req.user.did,
            history,
            totalRecords: history.length
        });
    }
);
