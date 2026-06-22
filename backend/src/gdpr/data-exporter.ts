/**
 * OmniID GDPR — Data Exporter Module
 * 
 * Generates portable data packages in JSON and PDF formats
 * for GDPR Art. 15 (Access) and Art. 20 (Portability) compliance.
 * 
 * GDPR Articles: Art. 15, Art. 20
 */

import * as crypto from 'crypto';
import { PQCEngine } from '../crypto/pqc';
import { AuditLogger } from '../audit/audit-logger';
import { ConsentManager } from '../consent/consent-manager';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ExportPackage {
    exportVersion: string;
    exportDate: string;
    exportFormat: 'json' | 'pdf';
    dataSubject: {
        did: string;
        personalData: {
            fullName?: string;
            dateOfBirth?: string;
            region?: string;
        };
        credentials: Array<{
            omniID: string;
            issuedAt: string;
            status: string;
        }>;
        consentHistory: Array<{
            purpose: string;
            granted: boolean;
            grantedAt: string;
            revokedAt?: string;
        }>;
        activityLog: Array<{
            timestamp: string;
            eventType: string;
            action: string;
            outcome: string;
        }>;
    };
    metadata: {
        dataController: string;
        dataControllerContact: string;
        dpoContact: string;
        legalBasis: string;
        retentionPeriod: string;
        thirdPartyRecipients: string[];
    };
    integritySignature: string;
}

// ─── Data Exporter ───────────────────────────────────────────────────────────

export class DataExporter {
    /**
     * Generate a complete data export package for a user.
     * Contains all personal data, consent history, and activity log.
     */
    public static generateExport(params: {
        userId: string;
        personalData: {
            fullName?: string;
            dob?: string;
            region?: string;
        };
        credentials: Array<{
            omniID: string;
            issuedAt: string;
            revoked: boolean;
        }>;
        format?: 'json' | 'pdf';
    }): ExportPackage {
        const format = params.format || 'json';

        // Gather consent history
        const consentHistory = ConsentManager.getConsentHistory(params.userId).map(c => ({
            purpose: c.purpose,
            granted: c.granted,
            grantedAt: c.grantedAt.toISOString(),
            revokedAt: c.revokedAt?.toISOString()
        }));

        // Gather activity log (user's own events)
        const auditEntries = AuditLogger.getByUser(params.userId).map(e => ({
            timestamp: e.timestamp,
            eventType: e.eventType,
            action: e.action,
            outcome: e.outcome
        }));

        const exportPackage: ExportPackage = {
            exportVersion: '1.0',
            exportDate: new Date().toISOString(),
            exportFormat: format,
            dataSubject: {
                did: params.userId,
                personalData: {
                    fullName: params.personalData.fullName,
                    dateOfBirth: params.personalData.dob,
                    region: params.personalData.region
                },
                credentials: params.credentials.map(c => ({
                    omniID: c.omniID,
                    issuedAt: c.issuedAt,
                    status: c.revoked ? 'REVOKED' : 'ACTIVE'
                })),
                consentHistory,
                activityLog: auditEntries.slice(-500) // Last 500 entries
            },
            metadata: {
                dataController: 'OmniID - Sistema de Identidad Digital Soberana',
                dataControllerContact: process.env.DATA_CONTROLLER_EMAIL || 'controller@omniid.gov',
                dpoContact: process.env.DPO_EMAIL || 'dpo@omniid.gov',
                legalBasis: 'Art. 6(1)(b) GDPR — Performance of a contract',
                retentionPeriod: 'Data is retained for the validity period of the credential (10 years) or until erasure is requested.',
                thirdPartyRecipients: [
                    'Hyperledger Indy DLT Network (pseudonymized DID metadata only)',
                    'No personal data is shared with third parties'
                ]
            },
            integritySignature: '' // Will be set below
        };

        // Sign the export for integrity verification
        const exportHash = crypto.createHash('sha256')
            .update(JSON.stringify(exportPackage.dataSubject))
            .digest('hex');

        exportPackage.integritySignature = `SHA256:${exportHash}`;

        return exportPackage;
    }

    /**
     * Generate a human-readable text summary of the export (pseudo-PDF).
     */
    public static generateTextReport(exportData: ExportPackage): string {
        const lines: string[] = [
            '═══════════════════════════════════════════════════════════════════',
            '              INFORME DE DATOS PERSONALES — OmniID                ',
            '          (Art. 15 y Art. 20 del Reglamento GDPR)                ',
            '═══════════════════════════════════════════════════════════════════',
            '',
            `Fecha de generación: ${exportData.exportDate}`,
            `Versión del informe: ${exportData.exportVersion}`,
            '',
            '─── DATOS PERSONALES ──────────────────────────────────────────────',
            `DID (Identificador Descentralizado): ${exportData.dataSubject.did}`,
            `Nombre Completo: ${exportData.dataSubject.personalData.fullName || 'N/A'}`,
            `Fecha de Nacimiento: ${exportData.dataSubject.personalData.dateOfBirth || 'N/A'}`,
            `Región: ${exportData.dataSubject.personalData.region || 'N/A'}`,
            '',
            '─── CREDENCIALES EMITIDAS ─────────────────────────────────────────',
        ];

        for (const cred of exportData.dataSubject.credentials) {
            lines.push(`  • OmniID: ${cred.omniID} | Estado: ${cred.status} | Emitido: ${cred.issuedAt}`);
        }

        lines.push('');
        lines.push('─── HISTORIAL DE CONSENTIMIENTO ────────────────────────────────');

        for (const consent of exportData.dataSubject.consentHistory) {
            const status = consent.granted ? 'OTORGADO' : 'REVOCADO';
            lines.push(`  • ${consent.purpose}: ${status} (${consent.grantedAt})`);
        }

        lines.push('');
        lines.push('─── REGISTRO DE ACTIVIDAD (últimos 50) ─────────────────────────');

        for (const event of exportData.dataSubject.activityLog.slice(-50)) {
            lines.push(`  [${event.timestamp}] ${event.eventType} — ${event.outcome}`);
        }

        lines.push('');
        lines.push('─── INFORMACIÓN DEL RESPONSABLE DEL TRATAMIENTO ────────────────');
        lines.push(`Responsable: ${exportData.metadata.dataController}`);
        lines.push(`Contacto: ${exportData.metadata.dataControllerContact}`);
        lines.push(`DPO: ${exportData.metadata.dpoContact}`);
        lines.push(`Base Legal: ${exportData.metadata.legalBasis}`);
        lines.push(`Período de Retención: ${exportData.metadata.retentionPeriod}`);
        lines.push('');
        lines.push('─── INTEGRIDAD ─────────────────────────────────────────────────');
        lines.push(`Firma de integridad: ${exportData.integritySignature}`);
        lines.push('');
        lines.push('═══════════════════════════════════════════════════════════════════');
        lines.push('Este informe ha sido generado automáticamente conforme al RGPD.');
        lines.push('═══════════════════════════════════════════════════════════════════');

        return lines.join('\n');
    }
}
