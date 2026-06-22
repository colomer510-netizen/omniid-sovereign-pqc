/**
 * OmniID GDPR — Audit Log API Routes
 * 
 * Provides endpoints for admins and DPOs to query and manage audit logs.
 * 
 * GDPR Articles: Art. 30 — Records of processing activities
 */

import { Router, Response } from 'express';
import { AuditLogger } from './audit-logger';
import { AuditEventType, AuditOutcome } from './audit-types';
import { requireAuth, requirePermission, AuthenticatedRequest } from '../auth/middleware';
import { Permission } from '../auth/rbac';

export const auditRouter = Router();

/**
 * GET /api/v1/audit/logs
 * Query audit logs with filters. Restricted to ADMIN and DPO roles.
 */
auditRouter.get('/logs',
    requireAuth,
    requirePermission(Permission.ADMIN_AUDIT_LOGS),
    (req: AuthenticatedRequest, res: Response) => {
        const {
            limit = '100',
            offset = '0',
            eventType,
            actorId,
            since,
            until,
            outcome
        } = req.query;

        const result = AuditLogger.getAll({
            limit: Math.min(parseInt(limit as string) || 100, 500),
            offset: parseInt(offset as string) || 0,
            eventType: eventType as AuditEventType | undefined,
            actorId: actorId as string | undefined,
            since: since ? new Date(since as string) : undefined,
            until: until ? new Date(until as string) : undefined,
            outcome: outcome as AuditOutcome | undefined
        });

        res.json({
            success: true,
            ...result,
            pagination: {
                limit: parseInt(limit as string) || 100,
                offset: parseInt(offset as string) || 0,
                hasMore: (parseInt(offset as string) || 0) + (parseInt(limit as string) || 100) < result.total
            }
        });
    }
);

/**
 * GET /api/v1/audit/integrity
 * Verify the integrity of the entire audit chain.
 */
auditRouter.get('/integrity',
    requireAuth,
    requirePermission(Permission.ADMIN_AUDIT_LOGS),
    (req: AuthenticatedRequest, res: Response) => {
        const integrity = AuditLogger.verifyIntegrity();
        res.json({
            success: true,
            integrity
        });
    }
);

/**
 * GET /api/v1/audit/statistics
 * Get audit log statistics for compliance reporting.
 */
auditRouter.get('/statistics',
    requireAuth,
    requirePermission(Permission.ADMIN_AUDIT_LOGS),
    (req: AuthenticatedRequest, res: Response) => {
        res.json({
            success: true,
            statistics: AuditLogger.getStatistics()
        });
    }
);

/**
 * GET /api/v1/audit/my-activity
 * Citizens can view their own audit trail (GDPR Art. 15 transparency).
 */
auditRouter.get('/my-activity',
    requireAuth,
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Authentication required.' });
        }

        const entries = AuditLogger.getByUser(req.user.did);
        res.json({
            success: true,
            entries: entries.slice(-100), // Last 100 entries
            total: entries.length
        });
    }
);

/**
 * GET /api/v1/audit/breach-report
 * Generate a breach report for GDPR Art. 33 notification.
 */
auditRouter.get('/breach-report',
    requireAuth,
    requirePermission(Permission.ADMIN_BREACH_REPORT),
    (req: AuthenticatedRequest, res: Response) => {
        const securityEvents = AuditLogger.getAll({
            eventType: AuditEventType.BREACH_DETECTED,
            limit: 500
        });

        res.json({
            success: true,
            gdprArticle: 'Art. 33 — Breach Notification Report',
            generatedAt: new Date().toISOString(),
            generatedBy: req.user?.did,
            events: securityEvents.entries,
            totalSecurityEvents: securityEvents.total,
            note: 'Supervisory authority must be notified within 72 hours of becoming aware of a personal data breach.'
        });
    }
);
