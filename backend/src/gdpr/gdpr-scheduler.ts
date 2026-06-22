/**
 * OmniID GDPR — Erasure Scheduler
 * 
 * Periodically checks for matured erasure requests (past the 7-day grace period)
 * and executes them automatically.
 * 
 * GDPR Articles: Art. 17 — Must process erasure within 30 days (Art. 12(3))
 */

import { DataEraser } from './data-eraser';

let schedulerInterval: NodeJS.Timeout | null = null;

/**
 * Start the erasure scheduler.
 * Checks every hour for matured requests.
 */
export function startErasureScheduler(
    deleteIdentityCallback: (userId: string) => {
        piiDeleted: boolean;
        credentialsRevoked: number;
        biometricDeleted: boolean;
    }
): void {
    if (schedulerInterval) {
        console.warn('[GDPR-SCHEDULER] Scheduler already running.');
        return;
    }

    console.log('[GDPR-SCHEDULER] Erasure scheduler started. Checking every hour for matured requests.');

    // Check immediately on startup
    processMaturedRequests(deleteIdentityCallback);

    // Then check every hour
    schedulerInterval = setInterval(() => {
        processMaturedRequests(deleteIdentityCallback);
    }, 60 * 60 * 1000); // 1 hour
}

/**
 * Process all matured erasure requests.
 */
function processMaturedRequests(
    deleteIdentityCallback: (userId: string) => {
        piiDeleted: boolean;
        credentialsRevoked: number;
        biometricDeleted: boolean;
    }
): void {
    const processed = DataEraser.processMatureRequests(deleteIdentityCallback);
    if (processed > 0) {
        console.log(`[GDPR-SCHEDULER] Processed ${processed} matured erasure request(s).`);
    }
}

/**
 * Stop the erasure scheduler.
 */
export function stopErasureScheduler(): void {
    if (schedulerInterval) {
        clearInterval(schedulerInterval);
        schedulerInterval = null;
        console.log('[GDPR-SCHEDULER] Erasure scheduler stopped.');
    }
}
