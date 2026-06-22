/**
 * OmniID GDPR — Enterprise Encryption Module (HashiCorp Vault Integration)
 * 
 * Replaces local HKDF encryption with a Sovereign KMS architecture using
 * Envelope Encryption via HashiCorp Vault's Transit Secret Engine.
 * 
 * GDPR Articles: Art. 32 — Security of processing
 */

import * as crypto from 'crypto';

// ─── Vault Configuration ─────────────────────────────────────────────────────

const VAULT_ADDR = process.env.VAULT_ADDR || 'http://127.0.0.1:8200';
const VAULT_TOKEN = process.env.VAULT_TOKEN;
const TRANSIT_KEY_NAME = process.env.VAULT_TRANSIT_KEY || 'omniid-gdpr-key';

// ─── Local Fallback (Development Only) ───────────────────────────────────────

const LOCAL_MASTER_KEY = process.env.OMNIID_MASTER_ENCRYPTION_KEY;
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;

let useVault = false;

/**
 * Check Vault connection status and configure engine.
 */
export async function initializeEncryptionEngine(): Promise<void> {
    if (VAULT_TOKEN && VAULT_ADDR) {
        try {
            // Check Vault health/status
            const response = await fetch(`${VAULT_ADDR}/v1/sys/health`, {
                headers: { 'X-Vault-Token': VAULT_TOKEN }
            });
            
            if (response.ok) {
                console.log('🛡️ [KMS] Conectado exitosamente a HashiCorp Vault.');
                useVault = true;
                return;
            }
        } catch (e) {
            console.error('🚨 [KMS] Error conectando a Vault. Configuración presente pero servicio inalcanzable.');
        }
    }

    console.warn('⚠️ [KMS] HASHICORP VAULT NO DETECTADO. Usando fallback criptográfico local (NO APTO PARA PRODUCCIÓN).');
    
    if (!LOCAL_MASTER_KEY || Buffer.from(LOCAL_MASTER_KEY, 'hex').length !== KEY_LENGTH) {
        console.warn('⚠️ [KMS] OMNIID_MASTER_ENCRYPTION_KEY inválida o ausente en .env. Generando llave temporal en memoria.');
        process.env.OMNIID_MASTER_ENCRYPTION_KEY = crypto.randomBytes(KEY_LENGTH).toString('hex');
    }
}

// ─── Types ───────────────────────────────────────────────────────────────────

export interface EncryptedBlob {
    ciphertext: string;   // Either Vault format (vault:v1:...) or Local Base64
    aad: string;          // The AAD used (DID)
    engine: 'vault' | 'local';
    context: string;
}

export interface EncryptedRecord {
    fullName?: EncryptedBlob;
    dob?: EncryptedBlob;
    region?: EncryptedBlob;
    biometricTemplate?: EncryptedBlob;
}

// ─── Vault API Client ────────────────────────────────────────────────────────

async function vaultEncrypt(plaintext: string, contextString: string): Promise<string> {
    const plaintextBase64 = Buffer.from(plaintext, 'utf8').toString('base64');
    const contextBase64 = Buffer.from(contextString, 'utf8').toString('base64');

    const res = await fetch(`${VAULT_ADDR}/v1/transit/encrypt/${TRANSIT_KEY_NAME}`, {
        method: 'POST',
        headers: {
            'X-Vault-Token': VAULT_TOKEN!,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            plaintext: plaintextBase64,
            context: contextBase64
        })
    });

    if (!res.ok) {
        const err = await res.text();
        throw new Error(`Vault encryption failed: ${err}`);
    }

    const data = await res.json();
    return data.data.ciphertext; // Format: vault:v1:xxxxxxxx
}

async function vaultDecrypt(ciphertext: string, contextString: string): Promise<string> {
    const contextBase64 = Buffer.from(contextString, 'utf8').toString('base64');

    const res = await fetch(`${VAULT_ADDR}/v1/transit/decrypt/${TRANSIT_KEY_NAME}`, {
        method: 'POST',
        headers: {
            'X-Vault-Token': VAULT_TOKEN!,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            ciphertext: ciphertext,
            context: contextBase64
        })
    });

    if (!res.ok) {
        throw new Error('Vault decryption failed. Posible manipulación de datos (AAD mismatch) o llave rotada/eliminada.');
    }

    const data = await res.json();
    return Buffer.from(data.data.plaintext, 'base64').toString('utf8');
}

// ─── Local Fallback Client (HKDF) ────────────────────────────────────────────

function deriveLocalKey(context: string): Buffer {
    const salt = crypto.createHash('sha256').update('omniid-gdpr-salt-v1').digest();
    const result = crypto.hkdfSync(
        'sha256',
        Buffer.from(process.env.OMNIID_MASTER_ENCRYPTION_KEY!, 'hex'),
        salt,
        `omniid:pii:${context}`,
        KEY_LENGTH
    );
    return Buffer.from(result);
}

function localEncrypt(plaintext: string, contextString: string): string {
    const derivedKey = deriveLocalKey(contextString);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, derivedKey, iv, { authTagLength: TAG_LENGTH });
    
    cipher.setAAD(Buffer.from(contextString, 'utf8'));
    
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    
    // Encode as custom string: iv.tag.ciphertext
    return `${iv.toString('base64')}.${tag.toString('base64')}.${encrypted.toString('base64')}`;
}

function localDecrypt(ciphertextString: string, contextString: string): string {
    const parts = ciphertextString.split('.');
    if (parts.length !== 3) throw new Error('Formato de cifrado local inválido.');
    
    const [ivB64, tagB64, encryptedB64] = parts;
    const derivedKey = deriveLocalKey(contextString);
    
    const decipher = crypto.createDecipheriv(ALGORITHM, derivedKey, Buffer.from(ivB64, 'base64'), { authTagLength: TAG_LENGTH });
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    decipher.setAAD(Buffer.from(contextString, 'utf8'));
    
    const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedB64, 'base64')), decipher.final()]);
    return decrypted.toString('utf8');
}

// ─── Unified Encryption Interface ────────────────────────────────────────────

/**
 * Encrypt a PII field using either Vault or Local Fallback.
 * @param plaintext - Data to encrypt
 * @param did - User's DID
 * @param context - Field context (e.g., 'fullName')
 */
export async function encryptPII(plaintext: string, did: string, context: string = 'default'): Promise<EncryptedBlob> {
    const contextString = `${did}:${context}`; // AAD binds data to User + Field
    let ciphertext: string;

    if (useVault) {
        ciphertext = await vaultEncrypt(plaintext, contextString);
    } else {
        ciphertext = localEncrypt(plaintext, contextString);
    }

    return {
        ciphertext,
        aad: did,
        engine: useVault ? 'vault' : 'local',
        context
    };
}

/**
 * Decrypt a PII field.
 */
export async function decryptPII(blob: EncryptedBlob): Promise<string> {
    const contextString = `${blob.aad}:${blob.context}`;

    if (blob.engine === 'vault') {
        if (!useVault) throw new Error('Cannot decrypt Vault ciphertext without a running Vault instance.');
        return await vaultDecrypt(blob.ciphertext, contextString);
    } else {
        return localDecrypt(blob.ciphertext, contextString);
    }
}

/**
 * Encrypt full identity record.
 */
export async function encryptIdentityPII(
    data: { fullName: string; dob: string; region: string; biometricTemplate?: number[] },
    did: string
): Promise<EncryptedRecord> {
    const record: EncryptedRecord = {};

    if (data.fullName) record.fullName = await encryptPII(data.fullName, did, 'fullName');
    if (data.dob) record.dob = await encryptPII(data.dob, did, 'dob');
    if (data.region) record.region = await encryptPII(data.region, did, 'region');
    
    if (data.biometricTemplate) {
        record.biometricTemplate = await encryptPII(JSON.stringify(data.biometricTemplate), did, 'biometric');
    }

    return record;
}

/**
 * Decrypt full identity record.
 */
export async function decryptIdentityPII(
    record: EncryptedRecord
): Promise<{ fullName?: string; dob?: string; region?: string; biometricTemplate?: number[] }> {
    const result: any = {};

    if (record.fullName) result.fullName = await decryptPII(record.fullName);
    if (record.dob) result.dob = await decryptPII(record.dob);
    if (record.region) result.region = await decryptPII(record.region);
    
    if (record.biometricTemplate) {
        const decryptedBio = await decryptPII(record.biometricTemplate);
        result.biometricTemplate = JSON.parse(decryptedBio);
    }

    return result;
}
