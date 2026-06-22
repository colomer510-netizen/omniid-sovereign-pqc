/**
 * OmniID GDPR — Immutable Audit Logger (SIEM / Wazuh Integration)
 * 
 * Logs events in a cryptographically linked chain for integrity (in-memory simulation)
 * AND writes events to the filesystem in NDJSON format for SIEM ingestion.
 * 
 * GDPR Articles: Art. 30 — Records of processing activities
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { AuditEntry, AuditEventType, AuditAction, AuditOutcome } from './audit-types';

export class AuditLogger {
    private static chain: AuditEntry[] = [];
    private static lastHash: string = crypto.createHash('sha256').update('omniid-genesis').digest('hex');
    private static logStream: fs.WriteStream;

    /**
     * Initializes the logger and sets up the NDJSON write stream for the SIEM.
     */
    public static initialize(logDir: string = path.join(__dirname, '../../logs')) {
        if (!fs.existsSync(logDir)) {
            fs.mkdirSync(logDir, { recursive: true });
        }

        const logFile = path.join(logDir, 'omniid-audit.log');
        
        // Open file stream in append mode
        this.logStream = fs.createWriteStream(logFile, { flags: 'a' });
        
        console.log(`📡 [SIEM] Audit Logger inicializado. Escribiendo logs NDJSON en: ${logFile}`);
        
        // Log startup
        this.log({
            eventType: AuditEventType.SYSTEM_STARTUP,
            action: AuditAction.CONFIGURE,
            actorId: 'SYSTEM',
            actorRole: 'SYSTEM',
            targetResource: 'audit-logger',
            ipAddressHash: 'system',
            details: { message: 'SIEM logging initialized' },
            outcome: AuditOutcome.SUCCESS
        } as any);
    }

    /**
     * Record a new event in the immutable chain and the SIEM log file.
     */
    public static log(eventData: Omit<AuditEntry, 'eventId' | 'timestamp' | 'integrityHash' | 'ipAddressHash'> & { ipAddressHash?: string, ipAddress?: string }): AuditEntry {
        const timestamp = new Date().toISOString();
        const eventId = crypto.randomUUID();

        // 1. Sanitize payload (DLP layer - remove raw PII before logging)
        const sanitizedDetails = this.sanitizeDetails(eventData.details);

        let ipHash = eventData.ipAddressHash || 'unknown';
        if (eventData.ipAddress) {
            ipHash = crypto.createHash('sha256').update(eventData.ipAddress).digest('hex');
        }

        // 2. Build the event
        const event: AuditEntry = {
            eventId,
            timestamp,
            ...eventData,
            ipAddressHash: ipHash,
            details: sanitizedDetails,
            integrityHash: ''
        };
        
        // Remove the temporary ipAddress field if it exists
        if ((event as any).ipAddress) {
            delete (event as any).ipAddress;
        }

        // 3. Cryptographically link the event
        event.integrityHash = this.hashEvent(event, this.lastHash);
        this.lastHash = event.integrityHash;

        // 4. Store in memory (for API querying / integrity checks)
        this.chain.push(event);

        // 5. Write to SIEM file (NDJSON format)
        if (this.logStream) {
            this.logStream.write(JSON.stringify(event) + '\n');
        }

        return event;
    }

    private static sanitizeDetails(details?: any): any {
        if (!details) return {};
        const sanitized = { ...details };
        const sensitiveKeys = ['password', 'token', 'secret', 'biometricTemplate', 'privateKey', 'seed'];
        
        for (const key of Object.keys(sanitized)) {
            if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk.toLowerCase()))) {
                sanitized[key] = '[REDACTED_BY_DLP]';
            }
        }
        return sanitized;
    }

    private static hashEvent(event: AuditEntry, prevHash: string): string {
        const dataToHash = `${event.eventId}${event.timestamp}${event.eventType}${event.actorId}${event.targetResource}${prevHash}`;
        return crypto.createHash('sha256').update(dataToHash).digest('hex');
    }

    // ─── API Compatibility Methods ───────────────────────────────────────────

    public static getAll(filters: any = {}): { entries: AuditEntry[], total: number } {
        let filtered = this.chain;

        if (filters.eventType) filtered = filtered.filter(e => e.eventType === filters.eventType);
        if (filters.actorId) filtered = filtered.filter(e => e.actorId === filters.actorId);
        if (filters.outcome) filtered = filtered.filter(e => e.outcome === filters.outcome);
        
        if (filters.since) {
            const sinceTime = new Date(filters.since).getTime();
            filtered = filtered.filter(e => new Date(e.timestamp).getTime() >= sinceTime);
        }
        if (filters.until) {
            const untilTime = new Date(filters.until).getTime();
            filtered = filtered.filter(e => new Date(e.timestamp).getTime() <= untilTime);
        }

        const total = filtered.length;
        const limit = filters.limit || 100;
        const offset = filters.offset || 0;

        // Apply pagination
        filtered = filtered.slice(offset, offset + limit);

        return {
            entries: filtered,
            total
        };
    }

    public static getByUser(userId: string): AuditEntry[] {
        return this.chain.filter(e => e.actorId === userId || e.targetResource === userId);
    }

    public static getStatistics(): any {
        const total = this.chain.length;
        const byType = this.chain.reduce((acc, curr) => {
            acc[curr.eventType] = (acc[curr.eventType] || 0) + 1;
            return acc;
        }, {} as Record<string, number>);

        const failedLogins = this.chain.filter(e => e.eventType === AuditEventType.LOGIN_FAILED).length;

        return {
            totalEvents: total,
            eventsByType: byType,
            failedLogins
        };
    }

    public static anonymizeUser(userId: string): number {
        let previousHash = crypto.createHash('sha256').update('omniid-genesis').digest('hex');
        let count = 0;
        
        for (let i = 0; i < this.chain.length; i++) {
            let modified = false;
            if (this.chain[i].actorId === userId) {
                this.chain[i].actorId = 'ANONYMIZED';
                modified = true;
            }
            if (this.chain[i].targetResource === userId) {
                this.chain[i].targetResource = 'ANONYMIZED';
                modified = true;
            }
            if (modified) count++;
            
            this.chain[i].integrityHash = this.hashEvent(this.chain[i], previousHash);
            previousHash = this.chain[i].integrityHash;
            
            if (i === this.chain.length - 1) {
                this.lastHash = previousHash;
            }
        }

        this.log({
            eventType: AuditEventType.DATA_ERASED,
            action: AuditAction.DELETE,
            actorId: 'SYSTEM',
            actorRole: 'SYSTEM',
            targetResource: 'ANONYMIZED',
            ipAddressHash: 'system',
            details: { message: `User logs anonymized per GDPR Art. 17. Count: ${count}` },
            outcome: AuditOutcome.SUCCESS
        } as any);

        return count;
    }

    public static verifyIntegrity(): { valid: boolean; brokenAtIndex: number } {
        let expectedPrevHash = crypto.createHash('sha256').update('omniid-genesis').digest('hex');

        for (let i = 0; i < this.chain.length; i++) {
            const event = this.chain[i];
            
            const calculatedSig = this.hashEvent(event, expectedPrevHash);
            if (event.integrityHash !== calculatedSig) {
                return { valid: false, brokenAtIndex: i };
            }

            expectedPrevHash = event.integrityHash;
        }

        return { valid: true, brokenAtIndex: -1 };
    }
}
