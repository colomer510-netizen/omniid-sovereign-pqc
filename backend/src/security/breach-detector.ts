/**
 * OmniID GDPR — Breach Detection Module
 * 
 * Monitors API activity patterns to detect potential security breaches.
 * Implements automatic escalation from alerts to defensive mode.
 * 
 * GDPR Articles: Art. 33 — Notification of a personal data breach (72h)
 *                Art. 34 — Communication to the data subject
 */

export enum AlertLevel {
    INFO = 0,
    WARNING = 1,      // Log + notify admin
    CRITICAL = 2,     // Block IP + notify DPO
    EMERGENCY = 3     // Read-only mode + notify supervisory authority
}

interface AnomalyEvent {
    timestamp: Date;
    type: string;
    source: string;      // IP or user identifier
    details: string;
    level: AlertLevel;
}

interface IPTracker {
    failedLogins: number;
    lastFailedAt: Date;
    verificationAttempts: number;
    exportRequests: number;
    blockedUntil?: Date;
}

/**
 * Breach Detection and Response Engine.
 * 
 * Monitors for:
 * 1. Credential stuffing (multiple failed logins from different IPs)
 * 2. Mass data exfiltration attempts
 * 3. Unusual admin access patterns
 * 4. DID enumeration attacks
 * 5. Abnormal revocation volumes
 */
export class BreachDetector {
    private ipTrackers = new Map<string, IPTracker>();
    private anomalyLog: AnomalyEvent[] = [];
    private defensiveMode = false;
    private readonly MAX_FAILED_LOGINS = 10;
    private readonly MAX_VERIFICATIONS_PER_MINUTE = 50;
    private readonly MAX_EXPORTS_PER_HOUR = 10;
    private readonly BLOCK_DURATION_MS = 30 * 60 * 1000; // 30 minutes
    private readonly CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

    private cleanupTimer: NodeJS.Timeout;

    constructor() {
        // Periodically clean up old tracking data
        this.cleanupTimer = setInterval(() => this.cleanup(), this.CLEANUP_INTERVAL_MS);
    }

    /**
     * Get or create an IP tracker entry.
     */
    private getTracker(ip: string): IPTracker {
        if (!this.ipTrackers.has(ip)) {
            this.ipTrackers.set(ip, {
                failedLogins: 0,
                lastFailedAt: new Date(0),
                verificationAttempts: 0,
                exportRequests: 0
            });
        }
        return this.ipTrackers.get(ip)!;
    }

    /**
     * Check if an IP is currently blocked.
     */
    public isBlocked(ip: string): boolean {
        const tracker = this.ipTrackers.get(ip);
        if (!tracker?.blockedUntil) return false;
        if (new Date() > tracker.blockedUntil) {
            tracker.blockedUntil = undefined;
            return false;
        }
        return true;
    }

    /**
     * Check if the system is in defensive (read-only) mode.
     */
    public isDefensiveMode(): boolean {
        return this.defensiveMode;
    }

    /**
     * Record a failed login attempt.
     */
    public recordFailedLogin(ip: string, username?: string): AlertLevel {
        const tracker = this.getTracker(ip);
        tracker.failedLogins++;
        tracker.lastFailedAt = new Date();

        // Pattern 1: Single IP brute force
        if (tracker.failedLogins >= this.MAX_FAILED_LOGINS) {
            this.blockIP(ip, 'Brute force attack detected');
            this.logAnomaly({
                timestamp: new Date(),
                type: 'BRUTE_FORCE',
                source: ip,
                details: `${tracker.failedLogins} failed login attempts. IP blocked for ${this.BLOCK_DURATION_MS / 60000} minutes.`,
                level: AlertLevel.CRITICAL
            });
            return AlertLevel.CRITICAL;
        }

        // Pattern 2: Moderate failed attempts
        if (tracker.failedLogins >= 5) {
            this.logAnomaly({
                timestamp: new Date(),
                type: 'SUSPICIOUS_LOGIN',
                source: ip,
                details: `${tracker.failedLogins} failed login attempts from same IP.`,
                level: AlertLevel.WARNING
            });
            return AlertLevel.WARNING;
        }

        return AlertLevel.INFO;
    }

    /**
     * Record a successful login (resets failed counter).
     */
    public recordSuccessfulLogin(ip: string): void {
        const tracker = this.getTracker(ip);
        tracker.failedLogins = 0;
    }

    /**
     * Record a verification attempt.
     */
    public recordVerification(ip: string, didFound: boolean): AlertLevel {
        const tracker = this.getTracker(ip);
        tracker.verificationAttempts++;

        // Pattern 3: DID enumeration (many verifications with unknown DIDs)
        if (!didFound) {
            this.logAnomaly({
                timestamp: new Date(),
                type: 'DID_ENUMERATION',
                source: ip,
                details: 'Verification attempt with non-existent DID.',
                level: AlertLevel.WARNING
            });
        }

        // Pattern 4: High-frequency verification
        if (tracker.verificationAttempts >= this.MAX_VERIFICATIONS_PER_MINUTE) {
            this.blockIP(ip, 'Excessive verification attempts');
            this.logAnomaly({
                timestamp: new Date(),
                type: 'EXCESSIVE_VERIFICATION',
                source: ip,
                details: `${tracker.verificationAttempts} verification attempts detected. Possible automated scanning.`,
                level: AlertLevel.CRITICAL
            });
            return AlertLevel.CRITICAL;
        }

        return AlertLevel.INFO;
    }

    /**
     * Record a data export request.
     */
    public recordExportRequest(ip: string, userId: string): AlertLevel {
        const tracker = this.getTracker(ip);
        tracker.exportRequests++;

        // Pattern 5: Mass data exfiltration
        if (tracker.exportRequests >= this.MAX_EXPORTS_PER_HOUR) {
            this.logAnomaly({
                timestamp: new Date(),
                type: 'MASS_EXFILTRATION',
                source: `${ip} (${userId})`,
                details: `${tracker.exportRequests} export requests in short period. Possible data exfiltration.`,
                level: AlertLevel.EMERGENCY
            });

            // Activate defensive mode
            this.activateDefensiveMode('Mass data exfiltration detected');
            return AlertLevel.EMERGENCY;
        }

        return AlertLevel.INFO;
    }

    /**
     * Record an admin access event outside business hours.
     */
    public recordAdminAccess(ip: string, userId: string): AlertLevel {
        const now = new Date();
        const hour = now.getHours();
        const dayOfWeek = now.getDay(); // 0 = Sunday, 6 = Saturday

        // Flag access outside business hours (weekdays 7am-8pm)
        const isOutsideHours = hour < 7 || hour > 20 || dayOfWeek === 0 || dayOfWeek === 6;

        if (isOutsideHours) {
            this.logAnomaly({
                timestamp: now,
                type: 'UNUSUAL_ADMIN_ACCESS',
                source: `${ip} (${userId})`,
                details: `Admin access at ${now.toISOString()} (outside business hours).`,
                level: AlertLevel.WARNING
            });
            return AlertLevel.WARNING;
        }

        return AlertLevel.INFO;
    }

    /**
     * Block an IP address for the configured duration.
     */
    private blockIP(ip: string, reason: string): void {
        const tracker = this.getTracker(ip);
        tracker.blockedUntil = new Date(Date.now() + this.BLOCK_DURATION_MS);
        console.error(`[BREACH] IP ${ip} BLOCKED: ${reason}`);
    }

    /**
     * Activate defensive (read-only) mode.
     * All write operations are suspended until manually deactivated.
     */
    private activateDefensiveMode(reason: string): void {
        this.defensiveMode = true;
        console.error(`[BREACH] ⚠️ DEFENSIVE MODE ACTIVATED: ${reason}`);
        console.error(`[BREACH] All write operations are suspended.`);
        console.error(`[BREACH] GDPR Art. 33: Supervisory authority must be notified within 72 hours.`);

        this.logAnomaly({
            timestamp: new Date(),
            type: 'DEFENSIVE_MODE_ACTIVATED',
            source: 'SYSTEM',
            details: reason,
            level: AlertLevel.EMERGENCY
        });
    }

    /**
     * Manually deactivate defensive mode (admin action).
     */
    public deactivateDefensiveMode(adminId: string): void {
        this.defensiveMode = false;
        console.log(`[BREACH] Defensive mode deactivated by ${adminId}.`);

        this.logAnomaly({
            timestamp: new Date(),
            type: 'DEFENSIVE_MODE_DEACTIVATED',
            source: adminId,
            details: 'Defensive mode manually deactivated by administrator.',
            level: AlertLevel.INFO
        });
    }

    /**
     * Log an anomaly event.
     */
    private logAnomaly(event: AnomalyEvent): void {
        this.anomalyLog.push(event);
        const prefix = event.level >= AlertLevel.CRITICAL ? '🚨' : '⚠️';
        console.warn(`${prefix} [BREACH] [${AlertLevel[event.level]}] ${event.type}: ${event.details}`);
    }

    /**
     * Get all anomaly events for reporting.
     */
    public getAnomalyLog(since?: Date): AnomalyEvent[] {
        if (since) {
            return this.anomalyLog.filter(e => e.timestamp >= since);
        }
        return [...this.anomalyLog];
    }

    /**
     * Get a summary for GDPR Art. 33 breach notification.
     */
    public getBreachReport(): object {
        const criticalEvents = this.anomalyLog.filter(
            e => e.level >= AlertLevel.CRITICAL
        );

        return {
            reportGeneratedAt: new Date().toISOString(),
            gdprArticle: 'Art. 33 — Notification of a personal data breach to the supervisory authority',
            defensiveModeActive: this.defensiveMode,
            totalAnomalies: this.anomalyLog.length,
            criticalAnomalies: criticalEvents.length,
            blockedIPs: Array.from(this.ipTrackers.entries())
                .filter(([, t]) => t.blockedUntil && t.blockedUntil > new Date())
                .map(([ip, t]) => ({ ip, blockedUntil: t.blockedUntil })),
            recentCriticalEvents: criticalEvents.slice(-20).map(e => ({
                timestamp: e.timestamp.toISOString(),
                type: e.type,
                source: e.source,
                details: e.details
            })),
            requiredAction: '72-hour notification to supervisory authority required if personal data breach confirmed.'
        };
    }

    /**
     * Clean up old tracking data to prevent memory leaks.
     */
    private cleanup(): void {
        const cutoff = new Date(Date.now() - 60 * 60 * 1000); // 1 hour ago

        for (const [ip, tracker] of this.ipTrackers.entries()) {
            if (tracker.lastFailedAt < cutoff && !tracker.blockedUntil) {
                this.ipTrackers.delete(ip);
            }
        }

        // Keep only last 10,000 anomaly events
        if (this.anomalyLog.length > 10000) {
            this.anomalyLog = this.anomalyLog.slice(-5000);
        }
    }

    /**
     * Express middleware that blocks requests from flagged IPs
     * and enforces defensive mode.
     */
    public middleware() {
        return (req: any, res: any, next: any) => {
            const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
                || req.ip || 'unknown';

            // Check IP block
            if (this.isBlocked(ip)) {
                return res.status(403).json({
                    success: false,
                    error: 'Access temporarily blocked due to suspicious activity.'
                });
            }

            // Check defensive mode for write operations
            if (this.defensiveMode && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
                // Allow GDPR read endpoints even in defensive mode
                if (!req.path.includes('/gdpr/my-data')) {
                    return res.status(503).json({
                        success: false,
                        error: 'System is in defensive mode. Write operations are temporarily suspended.'
                    });
                }
            }

            next();
        };
    }

    /**
     * Cleanup resources on shutdown.
     */
    public shutdown(): void {
        clearInterval(this.cleanupTimer);
    }
}

// Singleton instance
export const breachDetector = new BreachDetector();
