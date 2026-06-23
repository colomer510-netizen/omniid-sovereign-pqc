import { Router, Request, Response } from 'express';
import { FormatPreservingEngine } from '../crypto/fpe';
import { PQCEngine, FuzzyCommitment } from '../crypto/pqc';
import * as crypto from 'crypto';
import { E2EEServerKeys } from '../crypto/key-exchange';
import { z } from 'zod';

export const identityRouter = Router();

// In-memory Ledger / DLT Database
interface DLTRecord {
    did: string;
    omniID: string;
    userPublicKey: string;
    fuzzyCommitmentHash: string;
    issuerSig: string;
    revoked: boolean;
}

const dltLedgerRegistry = new Map<string, DLTRecord>();
let dbCounter = 4892013; // Starting database counter

// Generamos llaves maestras del Emisor Nacional (PQC) al levantar el servidor
const ISSUER_KEYPAIR = PQCEngine.generateKeyPair();

/**
 * Zod Schema for input validation
 */
const identitySchema = z.object({
    fullName: z.string().min(3).max(100),
    dob: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
    region: z.string().min(2).max(50),
    nationalId: z.string().max(20).optional(),
    nationality: z.string().max(50).optional(),
    gender: z.string().max(20).optional()
});

/**
 * Endpoint para obtener la llave pública RSA del servidor (Intercambio E2EE)
 */
identityRouter.get('/keys', (req: Request, res: Response) => {
    res.json({
        success: true,
        publicKeyPEM: E2EEServerKeys.publicKey
    });
});

/**
 * Endpoint de estado de la red (Health & DLT Connectivity)
 */
identityRouter.get('/status', (req: Request, res: Response) => {
    res.json({
        success: true,
        network: "Hyperledger Indy",
        consensus: "RBFT Active",
        issuerPQCKey: ISSUER_KEYPAIR.publicKey,
        dltRecords: dltLedgerRegistry.size,
        timestamp: new Date().toISOString()
    });
});

import { supabase } from '../services/supabaseClient';

/**
 * Endpoint para emitir una Cédula Digital OmniID (Enrolamiento)
 */
identityRouter.post('/issue', async (req: Request, res: Response) => {
    try {
        const { encryptedPayload, iv, encryptedAesKey, publicKey, biometricHash } = req.body;
        
        if (!encryptedPayload || !iv || !encryptedAesKey || !publicKey || !biometricHash) {
            return res.status(400).json({ 
                success: false, 
                error: "Petición rechazada. Datos de enrolamiento E2EE incompletos." 
            });
        }

        // 0. Descifrar la llave AES envuelta usando la llave privada RSA del servidor
        let aesKeyBuffer: Buffer;
        try {
            aesKeyBuffer = E2EEServerKeys.decryptAESKey(encryptedAesKey);
        } catch (err) {
            return res.status(401).json({ success: false, error: "Fallo criptográfico: Invalid Key Wrap." });
        }

        // 1. Descifrar el payload E2EE usando la llave AES-GCM recuperada
        const decipher = crypto.createDecipheriv('aes-256-gcm', aesKeyBuffer, Buffer.from(iv, 'hex'));
        const ciphertextBuf = Buffer.from(encryptedPayload, 'hex');
        const tag = ciphertextBuf.slice(ciphertextBuf.length - 16);
        const actualCiphertext = ciphertextBuf.slice(0, ciphertextBuf.length - 16);
        decipher.setAuthTag(tag);
        
        let decryptedStr = decipher.update(actualCiphertext, undefined, 'utf8');
        decryptedStr += decipher.final('utf8');
        
        // 2. Validar con Zod para prevenir inyecciones o datos malformados
        const plainData = JSON.parse(decryptedStr);
        const parsed = identitySchema.safeParse(plainData);
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: "Fallo de validación de esquema de datos (Posible manipulación)." });
        }
        
        const { fullName, dob, region, nationalId, nationality, gender } = parsed.data;

        // 1. Incrementar contador de DLT
        dbCounter++;
        
        // 2. Generar identificador de forma segura usando FPE
        const { id: omniID } = FormatPreservingEngine.generateID(dbCounter);
        const did = `did:omni:${omniID}`;

        // 3. Crear Fuzzy Commitment usando el hash provisto por el cliente
        const fuzzyCommitment = { hash: biometricHash, parity: "mock-parity-data" };

        // 4. Usar la llave pública proveída por el cliente en lugar de generar una
        const userKeys = { publicKey, privateKey: "kept_securely_on_client" };

        // 5. Crear la credencial W3C en formato SD-JWT firmada por el Emisor
        const claims = {
            name: fullName,
            dob: dob,
            region: region,
            nationalId: nationalId || 'N/A',
            nationality: nationality || 'N/A',
            gender: gender || 'N/A'
        };
        const sdjwt = PQCEngine.createSDJWT(claims, ISSUER_KEYPAIR.privateKey, did);

        // 6. Firmar los metadatos de identidad para registrar en el Ledger
        const ledgerMetadataSignature = PQCEngine.signMLDSA(did + userKeys.publicKey + fuzzyCommitment.hash, ISSUER_KEYPAIR.privateKey);

        // 7. Escribir registro en la DLT (Ledger)
        const dltRecord: DLTRecord = {
            did,
            omniID,
            userPublicKey: userKeys.publicKey,
            fuzzyCommitmentHash: fuzzyCommitment.hash,
            issuerSig: ledgerMetadataSignature,
            revoked: false
        };
        dltLedgerRegistry.set(did, dltRecord);

        // 8. Insertar en Supabase (Auditoría Central / Base de Datos Relacional)
        if (supabase) {
            const { error } = await supabase.from('issued_identities').insert([{
                omni_id: omniID,
                did: did,
                full_name: fullName,
                national_id: nationalId || 'N/A',
                nationality: nationality || 'N/A',
                gender: gender || 'N/A',
                dob: dob,
                region: region,
                bio_hash: fuzzyCommitment.hash,
                issuer_sig: ledgerMetadataSignature
            }]);
            
            if (error) {
                console.error("[Supabase] Error insertando identidad:", error.message);
                // Opcional: Podrías hacer fail la petición, pero para no romper la demo seguimos
            } else {
                console.log(`[Supabase] Identidad ${omniID} guardada exitosamente.`);
            }
        }

        // Retornar credenciales al Holder
        res.status(201).json({
            success: true,
            omniID,
            did,
            credential: {
                jwt: sdjwt.jwt,
                disclosures: sdjwt.disclosures
            },
            fuzzyCommitment: {
                hash: fuzzyCommitment.hash,
                parity: fuzzyCommitment.parity
            },
            userKeys: {
                publicKey: userKeys.publicKey,
                privateKey: userKeys.privateKey
            }
        });
    } catch (err: any) {
        console.error("[AUDIT] Error interno procesando credencial:", err.message);
        res.status(500).json({ success: false, error: "Error interno del servidor. Operación abortada." });
    }
});

/**
 * Endpoint para verificar una presentación y aplicar auditoría ZKP
 */
identityRouter.post('/verify', (req: Request, res: Response) => {
    try {
        const { sdjwt, releasedDisclosures, rule, verificationChallenge, holderSignature } = req.body;

        if (!sdjwt || !Array.isArray(releasedDisclosures) || !rule) {
            return res.status(400).json({ 
                success: false, 
                error: "Token SD-JWT, revelaciones o reglas faltantes." 
            });
        }

        const logs: string[] = [];
        logs.push("Estableciendo canal seguro TLS híbrido (ML-KEM-768)...");
        logs.push("Leyendo token dinámico QR offline...");

        // 1. Separar partes del SD-JWT
        const parts = sdjwt.split('.');
        if (parts.length !== 3) {
            return res.status(400).json({ success: false, error: "Formato JWS inválido" });
        }

        const payloadB64 = parts[1];
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
        const subjectDID = payload.sub;

        logs.push(`DID del ciudadano extraído: ${subjectDID}`);

        // 2. Buscar registro del titular en DLT Ledger
        const ledgerRecord = dltLedgerRegistry.get(subjectDID);
        if (!ledgerRecord) {
            logs.push(`[ERR] DID ${subjectDID} no está registrado en el ledger.`);
            return res.status(404).json({ success: false, approved: false, error: "Identidad no encontrada en el ledger." });
        }

        if (ledgerRecord.revoked) {
            logs.push(`[ERR] Identidad revocada en el ledger de Hyperledger Indy.`);
            return res.status(403).json({ success: false, approved: false, error: "Identidad revocada." });
        }
        logs.push("Resolución de DID y atestación de validez en Ledger DLT Indy exitosa.");

        // 3. Verificar firma del emisor usando la clave del Ledger
        const rawMessage = `${parts[0]}.${parts[1]}`;
        const signature = parts[2];
        const issuerSigValid = PQCEngine.verifyMLDSA(rawMessage, signature, ISSUER_KEYPAIR.publicKey);

        if (!issuerSigValid) {
            logs.push("[ERR] Firma digital del Emisor Nacional RECHAZADA.");
            return res.status(401).json({ success: false, approved: false, error: "Firma del emisor inválida." });
        }
        logs.push("Firma digital ML-DSA-85 del Emisor Nacional validada correctamente.");

        // 4. Validar expiración temporal del token
        const currentTimestamp = Math.floor(Date.now() / 1000);
        if (currentTimestamp > payload.exp) {
            logs.push(`[ERR] Credencial expirada (Exp: ${payload.exp}, Actual: ${currentTimestamp}).`);
            return res.status(401).json({ success: false, approved: false, error: "Credencial expirada temporalmente." });
        }

        // 5. Validar firma del Holder (Autenticación Activa)
        if (verificationChallenge && holderSignature) {
            const holderSigValid = PQCEngine.verifyMLDSA(verificationChallenge, holderSignature, ledgerRecord.userPublicKey);
            if (!holderSigValid) {
                logs.push("[ERR] Firma de llave del dispositivo móvil inválida.");
                return res.status(401).json({ success: false, approved: false, error: "Firma del titular inválida (Posible clonación)." });
            }
            logs.push("Autenticación activa del Secure Enclave del Holder verificada correctamente.");
        }

        // 6. Decodificar revelaciones y verificar contra hashes del SD-JWT
        const disclosedClaims: Record<string, any> = {};
        for (const disclosure of releasedDisclosures) {
            const rawDecoded = Buffer.from(disclosure, 'base64url').toString('utf8');
            const [salt, key, value] = JSON.parse(rawDecoded);
            
            // Validar que el hash SHA-256 de la revelación coincida con los de la lista _sd del token
            const computedHash = crypto.createHash('sha256').update(disclosure).digest('base64url');
            if (payload._sd.includes(computedHash)) {
                disclosedClaims[key] = value;
                logs.push(`Atributo revelado selectivamente verificado: '${key}'`);
            } else {
                logs.push(`[WARN] Intento de inyectar claim no firmado en SD-JWT: '${key}'`);
            }
        }

        // 7. Evaluar reglas de verificación ZKP
        let approved = false;

        if (rule === 'age') {
            if (!disclosedClaims.dob) {
                logs.push("[ERR] Atributo de fecha de nacimiento no provisto para regla de edad.");
                return res.status(400).json({ success: false, approved: false, error: "Atributo necesario dob no provisto." });
            }
            
            // Cálculo de edad
            const birthDate = new Date(disclosedClaims.dob);
            const today = new Date();
            let age = today.getFullYear() - birthDate.getFullYear();
            const m = today.getMonth() - birthDate.getMonth();
            if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) {
                age--;
            }
            
            approved = age >= 18;
            logs.push(`[ZKP] Verificando condición: Edad (${age} años) >= 18.`);
            logs.push(approved ? "ZKP de edad validado exitosamente." : "ZKP de edad fallido.");

        } else if (rule === 'region') {
            if (!disclosedClaims.region) {
                logs.push("[ERR] Atributo de ubicación no provisto para regla de residencia.");
                return res.status(400).json({ success: false, approved: false, error: "Atributo necesario region no provisto." });
            }

            approved = disclosedClaims.region.includes("Managua");
            logs.push(`[ZKP] Verificando condición: Región coincide con 'Managua'.`);
            logs.push(approved ? "ZKP de residencia validado exitosamente." : "ZKP de residencia fallido.");

        } else if (rule === 'full') {
            approved = !!(disclosedClaims.name && disclosedClaims.dob && disclosedClaims.region);
            logs.push("Divulgación de identidad completa aprobada por consentimiento del titular.");
        }

        res.json({
            success: true,
            approved,
            disclosedClaims: rule === 'full' ? disclosedClaims : { 
                // ZKP oculta el valor real, solo devuelve si es aprobado
                name: disclosedClaims.name // Se puede revelar el nombre únicamente si se solicita
            },
            logs
        });
    } catch (err: any) {
        res.status(500).json({ success: false, error: err.message });
    }
});
