import { FormatPreservingEngine } from './crypto/fpe';
import { PQCEngine } from './crypto/pqc';

function testFlow() {
    console.log("==========================================");
    console.log("INICIANDO PRUEBA DE INTEGRACIÓN OMNIID");
    console.log("==========================================");

    // 1. Probar FPE (Format-Preserving Encryption)
    console.log("\n[1] Probando Generación de ID FPE (FF1-like)...");
    const count1 = 4892014;
    const count2 = 4892015;
    
    const id1 = FormatPreservingEngine.generateID(count1);
    const id2 = FormatPreservingEngine.generateID(count2);
    
    console.log(`Contador ${count1} -> ID: ${id1.id} (Int: ${id1.num})`);
    console.log(`Contador ${count2} -> ID: ${id2.id} (Int: ${id2.num})`);
    
    if (id1.id === id2.id) {
        throw new Error("ERROR: ¡Se detectó colisión en FPE!");
    }
    console.log("FPE verificado: IDs únicos y formateados correctamente.");

    // 2. Probar Fuzzy Commitment (Biometría)
    console.log("\n[2] Probando Fuzzy Commitment Scheme...");
    const originalTemplate = [142, 99, 44, 212, 85, 12, 190, 77];
    const similarTemplate = [142, 99, 45, 212, 84, 12, 190, 77]; // 2 valores cambiados ligeramente (dentro del umbral)
    const distinctTemplate = [10, 20, 30, 40, 50, 60, 70, 80];    // Completamente diferente

    const commitment = PQCEngine.createFuzzyCommitment(originalTemplate);
    console.log(`Fuzzy Commitment creado. Hash H(s): ${commitment.hash}`);
    
    const verifySimilar = PQCEngine.verifyFuzzyCommitment(similarTemplate, commitment);
    const verifyDistinct = PQCEngine.verifyFuzzyCommitment(distinctTemplate, commitment);
    
    console.log(`Verificar similar (ruido aceptado): ${verifySimilar ? "APROBADO (Esperado)" : "RECHAZADO"}`);
    console.log(`Verificar distinto (ruido fuera del umbral): ${verifyDistinct ? "APROBADO" : "RECHAZADO (Esperado)"}`);
    
    if (!verifySimilar || verifyDistinct) {
        throw new Error("ERROR: Falla de consistencia en Fuzzy Commitment Scheme.");
    }

    // 3. Probar Emisión de SD-JWT y Firma ML-DSA-65
    console.log("\n[3] Probando Generación de SD-JWT con firmas PQC ML-DSA-65...");
    const issuerKeys = PQCEngine.generateKeyPair();
    const holderKeys = PQCEngine.generateKeyPair();
    const userDID = `did:omni:${id1.id}`;

    const claims = {
        name: "Joaquin Obando",
        dob: "2000-05-15",
        region: "Managua, Nicaragua"
    };

    const sdjwt = PQCEngine.createSDJWT(claims, issuerKeys.privateKey, userDID);
    console.log(`Token SD-JWT emitido:\n${sdjwt.jwt.substring(0, 100)}...`);
    console.log("Revelaciones generadas (Base64):");
    console.log(`  - Nombre: ${sdjwt.disclosures.name}`);
    console.log(`  - Fecha Nac: ${sdjwt.disclosures.dob}`);
    console.log(`  - Región: ${sdjwt.disclosures.region}`);

    // 4. Probar Autenticación Activa y Verificación ZKP (Simulado por la API)
    console.log("\n[4] Probando Verificación ZKP de Edad (+18) en SD-JWT...");
    
    // El usuario revela selectivamente solo 'dob' para probar mayoría de edad
    const ageVerificationPayload = sdjwt.jwt;
    const releasedDisclosures = [sdjwt.disclosures.dob]; // Solo liberamos fecha de nacimiento

    // Parseamos token manualmente en el test
    const parts = ageVerificationPayload.split('.');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const signature = parts[2];

    // Verificar firma del emisor
    const rawMessage = `${parts[0]}.${parts[1]}`;
    const isIssuerSigValid = PQCEngine.verifyMLDSA(rawMessage, signature, issuerKeys.publicKey);
    console.log(`Firma digital del Emisor Nacional (ML-DSA-65): ${isIssuerSigValid ? "VÁLIDA (Esperada)" : "INVÁLIDA"}`);

    if (!isIssuerSigValid) {
        throw new Error("ERROR: Firma de emisor ML-DSA inválida.");
    }

    // Verificar hash de divulgación
    const dobDisclosure = releasedDisclosures[0];
    const crypto = require('crypto');
    const computedHash = crypto.createHash('sha256').update(dobDisclosure).digest('base64url');
    const isHashInJWT = payload._sd.includes(computedHash);
    console.log(`Divulgación selectiva de dob en _sd del JWT: ${isHashInJWT ? "PRESENTE (Esperada)" : "AUSENTE"}`);

    if (!isHashInJWT) {
        throw new Error("ERROR: Hash de divulgación selectiva no encontrado en JWT.");
    }

    // Comprobar la edad
    const rawDecoded = Buffer.from(dobDisclosure, 'base64url').toString('utf8');
    const [salt, key, dobValue] = JSON.parse(rawDecoded);
    console.log(`Atributo revelado descifrado: ${key} = ${dobValue}`);

    const birthDate = new Date(dobValue);
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    if (today.getMonth() < birthDate.getMonth() || (today.getMonth() === birthDate.getMonth() && today.getDate() < birthDate.getDate())) {
        age--;
    }
    const isOver18 = age >= 18;
    console.log(`Evaluación ZKP de Edad (${age} años) >= 18: ${isOver18 ? "APROBADO (Esperado)" : "RECHAZADO"}`);

    if (!isOver18) {
        throw new Error("ERROR: Evaluación de edad incorrecta.");
    }

    console.log("\n==========================================");
    console.log("¡TODAS LAS PRUEBAS PASARON EXITOSAMENTE!");
    console.log("==========================================");
}

testFlow();
