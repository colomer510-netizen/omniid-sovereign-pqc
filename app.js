// OmniID - Sovereign Identity Simulator Engine

// Global State
let state = {
    userCount: 4892013, // Simulated sequential DB counter
    currentUser: null,
    activeRule: 'age', // 'age', 'region', 'full'
    qrTimer: null,
    qrSecondsLeft: 15,
    qrPayload: '',
    walletUnlocked: false,
    biometricsCaptured: false,
    simulatedBioTemplate: null
};

// Colors for terminal logs
const COLORS = {
    system: 'text-muted',
    ok: 'text-emerald',
    info: 'text-cyan',
    warn: 'text-purple',
    error: 'text-rose'
};

// Initialize Application
document.addEventListener("DOMContentLoaded", () => {
    logTerminal(window.getT("log_init"), COLORS.info);
    logTerminal(window.getT("log_keys"), COLORS.system);
    logTerminal("Estableciendo conexión segura Zero Trust en puerto local...", COLORS.system);
    logTerminal(window.getT("log_ready"), COLORS.ok);
    
    // Enroll default user to showcase something initially
    enrollUser();
});

// Log to Verifier Terminal
function logTerminal(message, colorClass = COLORS.system) {
    const term = document.getElementById("verifier-terminal-log");
    if (!term) return;
    const time = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    line.className = `term-line ${colorClass}`;
    line.textContent = `[${time}] ${message}`;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
}

// Clear Terminal Logs
function clearTerminal() {
    const term = document.getElementById("verifier-terminal-log");
    if (term) term.innerHTML = '';
    logTerminal("Consola de auditoría limpiada.", COLORS.system);
}

// Log to Mobile Wallet Console
function logWallet(message, colorClass = COLORS.system) {
    const consoleLogs = document.getElementById("wallet-log-console");
    if (!consoleLogs) return;
    const line = document.createElement("div");
    line.className = `log-line ${colorClass}`;
    line.innerText = message;
    consoleLogs.appendChild(line);
    consoleLogs.scrollTop = consoleLogs.scrollHeight;
}

// Format-Preserving Encryption (FF1-like) Algorithm
// Maps counter sequentially to deterministic, collision-free, pseudorandom [L][6N][L][7N]
function generateFormatPreservingID(counter) {
    const M = 6760000000000000n; // Total possible combinations
    const primeMultiplier = 492098239019231n; // Relative prime multiplier
    const offset = 932019382103987n; // Seed offset
    
    // Linear Congruential Permutation (LCG with prime index)
    const seed = (BigInt(counter) * primeMultiplier + offset) % M;
    
    let current = seed;
    
    // Extract parameters
    const letter1Idx = Number(current % 26n);
    current /= 26n;
    
    const num1Val = Number(current % 1000000n);
    current /= 1000000n;
    
    const letter2Idx = Number(current % 26n);
    current /= 26n;
    
    const num2Val = Number(current % 10000000n);
    
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const letter1 = alphabet[letter1Idx];
    const letter2 = alphabet[letter2Idx];
    
    const num1Str = String(num1Val).padStart(6, '0');
    const num2Str = String(num2Val).padStart(7, '0');
    
    return `${letter1}${num1Str}${letter2}${num2Str}`;
}

// Capture Biometrics Simulation
function triggerBioScan() {
    const scanner = document.getElementById("bio-scanner");
    const status = document.getElementById("bio-scan-status");
    
    if (state.biometricsCaptured) {
        // Reset capture
        state.biometricsCaptured = false;
        state.simulatedBioTemplate = null;
        scanner.classList.remove("scanning");
        status.innerText = "Capturar Huella Digital";
        status.style.color = "var(--text-secondary)";
        return;
    }
    
    scanner.classList.add("scanning");
    status.innerText = "Escaneando minucias...";
    status.style.color = "var(--accent-indigo)";
    
    setTimeout(() => {
        state.biometricsCaptured = true;
        // Generate random minutiae vector
        state.simulatedBioTemplate = Array.from({length: 8}, () => Math.floor(Math.random() * 256));
        scanner.classList.remove("scanning");
        status.innerText = "Huella Capturada (Correctamente)";
        status.style.color = "var(--accent-emerald)";
        logTerminal("Biometría facial/dactilar procesada en HSM local.", COLORS.ok);
    }, 1500);
}

// --- Web Crypto API Integration (E2EE & Real Cryptography) ---

async function generateRealHash(dataArray) {
    const data = new Uint8Array(dataArray);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return "0x" + hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function generateUserKeys() {
    const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-384" },
        true,
        ["sign", "verify"]
    );
    const exportedPublicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const exportedPublicKeyBuffer = new Uint8Array(exportedPublicKey);
    const pubKeyBase64 = btoa(String.fromCharCode.apply(null, exportedPublicKeyBuffer));
    return { keyPair, pubKeyBase64 };
}

async function encryptPayloadE2EE(dataObj) {
    const aesKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(JSON.stringify(dataObj));
    const ciphertextBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        aesKey,
        encodedData
    );
    const ciphertextArray = Array.from(new Uint8Array(ciphertextBuffer));
    const ciphertextHex = ciphertextArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
    
    // FETCH BACKEND PUBLIC KEY
    let rsaPubKey;
    try {
        const keyRes = await fetch("http://localhost:3000/api/v1/identities/keys");
        const keyData = await keyRes.json();
        const pem = keyData.publicKeyPEM;
        
        // Parse PEM to ArrayBuffer
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";
        const pemContents = pem.replace(pemHeader, "").replace(pemFooter, "").replace(/\s/g, '');
        const binaryDerString = window.atob(pemContents);
        const binaryDer = new Uint8Array(binaryDerString.length);
        for (let i = 0; i < binaryDerString.length; i++) {
            binaryDer[i] = binaryDerString.charCodeAt(i);
        }
        
        rsaPubKey = await crypto.subtle.importKey(
            "spki",
            binaryDer.buffer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["encrypt"]
        );
        logTerminal("[WEB CRYPTO] Llave pública RSA del backend importada exitosamente.", COLORS.ok);
    } catch (e) {
        logTerminal("[ERR] No se pudo obtener la llave pública RSA del servidor.", COLORS.error);
        throw e;
    }

    // ENCRYPT AES KEY WITH RSA-OAEP
    logTerminal("[WEB CRYPTO] Envolviendo llave AES con RSA-OAEP...", COLORS.system);
    const encryptedAesKeyBuf = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        rsaPubKey,
        rawAesKey
    );
    const encryptedAesKeyBase64 = window.btoa(String.fromCharCode(...new Uint8Array(encryptedAesKeyBuf)));

    const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');

    return { ciphertextHex, ivHex, encryptedAesKey: encryptedAesKeyBase64 };
}

// -----------------------------------------------------------

// Enroll / Issue Credential
async function enrollUser() {
    const fullName = document.getElementById("input-fullname").value.trim() || "Joaquin Obando";
    const dobInput = document.getElementById("input-dob").value;
    const region = document.getElementById("input-region").value;
    const nationalId = document.getElementById("input-national-id").value;
    const nationality = document.getElementById("input-nationality").value;
    const gender = document.getElementById("input-gender").value;
    
    const bioTemplate = state.simulatedBioTemplate || Array.from({length: 8}, () => Math.floor(Math.random() * 256));
    
    logTerminal("[WEB CRYPTO] Generando par de llaves asimétricas ECDSA P-384...", COLORS.system);
    const { keyPair, pubKeyBase64 } = await generateUserKeys();
    logTerminal(`[WEB CRYPTO] Llave pública generada: ${pubKeyBase64.substring(0, 40)}...`, COLORS.ok);
    
    logTerminal("[WEB CRYPTO] Encriptando payload con AES-GCM (E2EE)...", COLORS.system);
    const payloadToEncrypt = { fullName, dob: dobInput, region, nationalId, nationality, gender };
    const { ciphertextHex, ivHex, encryptedAesKey } = await encryptPayloadE2EE(payloadToEncrypt);
    logTerminal(`[WEB CRYPTO] Ciphertext: ${ciphertextHex.substring(0, 40)}...`, COLORS.ok);

    const realBioHash = await generateRealHash(bioTemplate);
    logTerminal(`[WEB CRYPTO] Hash biométrico SHA-256 generado.`, COLORS.ok);

    logTerminal("Iniciando acuñación de credencial PQC con el servidor...", COLORS.system);
    
    let data;
    try {
        const response = await fetch("http://localhost:3000/api/v1/identities/issue", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                encryptedPayload: ciphertextHex,
                iv: ivHex,
                encryptedAesKey: encryptedAesKey,
                publicKey: pubKeyBase64,
                biometricHash: realBioHash
            })
        });
        
        data = await response.json();
    } catch (e) {
        logTerminal(window.getT("log_fallback"), COLORS.warn);
        const mockId = generateFormatPreservingID(state.userCount++);
        data = {
            success: true,
            omniID: mockId,
            did: `did:omni:vdr:${mockId.toLowerCase()}`,
            fuzzyCommitment: { hash: realBioHash },
            credential: { jwt: `eyJhbGciOiJNTFBEU0E4NSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtb2NrIn0.z6MkmLmQ8...yT6G4rD1sH`, disclosures: [] },
            userKeys: { publicKey: pubKeyBase64 }
        };
    }
    
    if (!data.success) {
        logTerminal(`[ERR] Fallo de enrolamiento: ${data.error}`, COLORS.error);
        return;
    }

        const issueDate = new Date().toISOString().split('T')[0];
        const expiryDate = new Date(new Date().setFullYear(new Date().getFullYear() + 10)).toISOString().split('T')[0];
        
        state.currentUser = {
            name: fullName,
            dob: dobInput,
            region: region,
            nationalId: nationalId,
            nationality: nationality,
            gender: gender,
            omniID: data.omniID,
            did: data.did,
            bioHash: data.fuzzyCommitment.hash,
            issuerSig: data.credential.jwt.split('.')[2].substring(0, 18) + "...", 
            issueDate: issueDate,
            expiryDate: expiryDate,
            rawCredential: data.credential,
            userKeys: data.userKeys
        };
        
        // Show results in Issuer Box
        document.getElementById("res-did").innerText = data.did;
        document.getElementById("res-id").innerText = data.omniID;
        document.getElementById("enroll-result").classList.remove("hidden");
        
        // Sync to Virtual Web Credential Visualizer
        document.getElementById("card-name").innerText = formatLastNameFirst(fullName);
        document.getElementById("card-dob").innerText = dobInput;
        document.getElementById("card-national-id").innerText = nationalId;
        document.getElementById("card-nationality").innerText = nationality;
        document.getElementById("card-gender").innerText = gender;
        document.getElementById("card-id").innerText = formatIdDashes(data.omniID);
        document.getElementById("card-issue").innerText = issueDate;
        document.getElementById("card-expiry").innerText = expiryDate;
        document.getElementById("card-bio-hash").innerText = data.fuzzyCommitment.hash;
        document.getElementById("card-issuer-sig").innerText = state.currentUser.issuerSig;
        document.getElementById("card-photo").classList.add("active");

        // Reset mobile wallet lock state
        state.walletUnlocked = false;
        document.getElementById("wallet-auth-screen").classList.remove("hidden");
        document.getElementById("wallet-main-screen").classList.add("hidden");
        
        // Clear dynamic QR loops
        if (state.qrTimer) {
            clearInterval(state.qrTimer);
            state.qrTimer = null;
        }
        
        logTerminal(`Acuñada nueva credencial OmniID para ${fullName}.`, COLORS.ok);
        logTerminal(`DID Document publicado en el backend Ledger: ${data.did}`, COLORS.system);
    } catch (err) {
        logTerminal(`[ERR] Error conectando con el backend: ${err.message}`, COLORS.error);
    }
}

// Helpers for string formatting
function formatLastNameFirst(name) {
    const parts = name.split(" ");
    if (parts.length > 1) {
        const last = parts.slice(1).join(" ").toUpperCase();
        const first = parts[0].toUpperCase();
        return `${last} ${first}`;
    }
    return name.toUpperCase();
}

function formatIdDashes(idStr) {
    // Structure: [Letra] + [6 números] + [Letra] + [7 números]
    // A123456B1234567 -> A-123456-B-1234567
    if (idStr.length === 15) {
        return `${idStr[0]}-${idStr.substring(1, 7)}-${idStr[7]}-${idStr.substring(8)}`;
    }
    return idStr;
}


// Unlock Mobile Wallet using WebAuthn (Hardware Biometrics)
async function unlockWalletWithBiometrics() {
    logWallet("Iniciando validación biométrica de hardware (FIDO2)...");
    
    // Fallback to simulation if WebAuthn is not supported or not in secure context
    if (!window.PublicKeyCredential || !window.isSecureContext) {
        logWallet("[WARN] WebAuthn requiere HTTPS o localhost. Usando simulación.");
        setTimeout(finishWalletUnlock, 800);
        return;
    }

    try {
        const userId = state.currentUser ? state.currentUser.omniID : "test-user-" + Date.now();
        const userName = state.currentUser ? state.currentUser.name : "Usuario";
        
        // FIDO2 / WebAuthn Options to trigger local biometric prompt
        const publicKeyCredentialCreationOptions = {
            challenge: Uint8Array.from("random_challenge_string_for_demo", c => c.charCodeAt(0)),
            rp: {
                name: "OmniID Sovereign Wallet",
            },
            user: {
                id: Uint8Array.from(userId, c => c.charCodeAt(0)),
                name: userName,
                displayName: userName,
            },
            pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
            authenticatorSelection: {
                authenticatorAttachment: "platform", // Forces hardware biometric (Windows Hello, FaceID, TouchID, etc)
                userVerification: "required"
            },
            timeout: 60000,
            attestation: "none"
        };

        // This triggers the OS biometric prompt
        await navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions
        });

        logWallet("[OK] Validación Biométrica (WebAuthn) Exitosa.", COLORS.ok);
        finishWalletUnlock();

    } catch (err) {
        logWallet(`[ERR] Validación biométrica fallida o cancelada.`, COLORS.error);
        console.error(err);
    }
}

function finishWalletUnlock() {
    state.walletUnlocked = true;
    
    // Sync wallet data if user exists
    if (state.currentUser) {
        document.getElementById("wallet-name").innerText = state.currentUser.name;
        document.getElementById("wallet-id").innerText = formatIdDashes(state.currentUser.omniID);
        document.getElementById("wallet-national-id").innerText = state.currentUser.nationalId;
        document.getElementById("wallet-dob").innerText = state.currentUser.dob;
        document.getElementById("wallet-gender").innerText = state.currentUser.gender;
        document.getElementById("wallet-nationality").innerText = state.currentUser.nationality;
        
        // Dynamic age calculation
        if (state.currentUser.dob) {
            const age = calculateAge(state.currentUser.dob);
            document.getElementById("wallet-age").innerText = `${age} ${window.getT("years")}`;
        }
    }
    
    // Sync profile photo
    document.getElementById("wallet-photo").style.backgroundImage = "url('data:image/svg+xml;utf8,<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"%238b5cf6\" stroke-width=\"1.5\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 4a3 3 0 1 1-3 3 3 3 0 0 1 3-3zm0 12.2a7.2 7.2 0 0 1-6-3.2c.04-2 4-3.1 6-3.1s5.96 1.1 6 3.1a7.2 7.2 0 0 1-6 3.2z\"/></svg>')";
    
    // UI screens transition
    document.getElementById("wallet-auth-screen").classList.add("hidden");
    document.getElementById("wallet-main-screen").classList.remove("hidden");
    
    logWallet("[OK] Desbloqueo Seguro Exitoso.", COLORS.ok);
    logWallet("[OK] SQLCipher cargado en memoria protegida.", COLORS.ok);
    
    // Start generating dynamic QR Codes
    startQRGenerator();
}

// Helper to calculate age
function calculateAge(dobString) {
    const today = new Date();
    const birthDate = new Date(dobString);
    let age = today.getFullYear() - birthDate.getFullYear();
    const m = today.getMonth() - birthDate.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) {
        age--;
    }
    return age;
}

// QR Code Generator & Timer
function startQRGenerator() {
    generateDynamicQR();
    
    state.qrTimer = setInterval(() => {
        state.qrSecondsLeft--;
        updateTimerUI();
        
        if (state.qrSecondsLeft <= 0) {
            // Trigger regenerate
            document.getElementById("qr-expired-msg").classList.remove("hidden");
            clearInterval(state.qrTimer);
            
            setTimeout(() => {
                state.qrSecondsLeft = 15;
                document.getElementById("qr-expired-msg").classList.add("hidden");
                generateDynamicQR();
                startQRGenerator();
            }, 600);
        }
    }, 1000);
}

function updateTimerUI() {
    const secSpan = document.getElementById("timer-seconds");
    const indicator = document.getElementById("timer-indicator");
    
    secSpan.innerText = `${state.qrSecondsLeft}s`;
    
    // Circular progress stroke calculation
    // Max offset = 94, representing 15 seconds
    const progress = (15 - state.qrSecondsLeft) / 15;
    const offset = progress * 94;
    indicator.style.strokeDashoffset = offset;
    
    if (state.qrSecondsLeft < 5) {
        indicator.style.stroke = "var(--accent-rose)";
    } else {
        indicator.style.stroke = "var(--accent-emerald)";
    }
}

// Generate stylized dynamic QR code payload
function generateDynamicQR() {
    const user = state.currentUser;
    if (!user || !user.rawCredential) return;
    
    // Usamos el SD-JWT real generado por el servidor
    const token = user.rawCredential.jwt;
    state.qrPayload = token;
    
    // Render dynamic visual QR using grid pattern
    renderVisualQR(token);
    
    logWallet(`[PQC] Refrescando código QR dinámico desde Billetera.`, COLORS.system);
    logWallet(`[PQC] Certificado SD-JWT con firma ML-DSA listo.`, COLORS.ok);
}

// Draws a simulated scannable grid inside SVG to serve as dynamic QR
function renderVisualQR(dataString) {
    const svg = document.getElementById("qr-svg-code");
    if (!svg) return;
    
    svg.innerHTML = '';
    
    // Draw target position boxes (top-left, top-right, bottom-left)
    drawQRBox(svg, 2, 2, 22);
    drawQRBox(svg, 76, 2, 22);
    drawQRBox(svg, 2, 76, 22);
    
    // Seeded random dots generator depending on dataString hash
    let hash = 0;
    for (let i = 0; i < dataString.length; i++) {
        hash = dataString.charCodeAt(i) + ((hash << 5) - hash);
    }
    
    // Draw random-looking data pixels conforming to dataString
    const size = 100;
    const moduleSize = 4;
    const padding = 26;
    
    for (let x = 0; x < size; x += moduleSize) {
        for (let y = 0; y < size; y += moduleSize) {
            // Skip position target boxes areas
            if ((x < padding && y < padding) || 
                (x > size - padding && y < padding) || 
                (x < padding && y > size - padding)) {
                continue;
            }
            
            // Deterministic pixel grid
            const randomVal = Math.abs(Math.sin(hash + x * y)) * 10;
            if (randomVal > 5) {
                const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
                rect.setAttribute("x", x);
                rect.setAttribute("y", y);
                rect.setAttribute("width", moduleSize - 0.5);
                rect.setAttribute("height", moduleSize - 0.5);
                rect.setAttribute("fill", "#0f172a"); // Dark slate
                rect.setAttribute("rx", "1");
                svg.appendChild(rect);
            }
        }
    }
    
    // Add glowing shield logo inside the center of QR code
    const centerShield = document.createElementNS("http://www.w3.org/2000/svg", "path");
    centerShield.setAttribute("d", "M44 42L50 40L56 42V48C56 52 50 56 50 56C50 56 44 52 44 48V42Z");
    centerShield.setAttribute("fill", "url(#qr-shield-grad)");
    
    const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
    const grad = document.createElementNS("http://www.w3.org/2000/svg", "linearGradient");
    grad.setAttribute("id", "qr-shield-grad");
    grad.innerHTML = `<stop stop-color="#8b5cf6"/><stop offset="1" stop-color="#10b981"/>`;
    defs.appendChild(grad);
    
    svg.appendChild(defs);
    svg.appendChild(centerShield);
}

function drawQRBox(svg, x, y, size) {
    const outer = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    outer.setAttribute("x", x);
    outer.setAttribute("y", y);
    outer.setAttribute("width", size);
    outer.setAttribute("height", size);
    outer.setAttribute("fill", "none");
    outer.setAttribute("stroke", "#6366f1"); // Indigo Accent
    outer.setAttribute("stroke-width", "3.5");
    outer.setAttribute("rx", "4");
    
    const inner = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    inner.setAttribute("x", x + 5.5);
    inner.setAttribute("y", y + 5.5);
    inner.setAttribute("width", size - 11);
    inner.setAttribute("height", size - 11);
    inner.setAttribute("fill", "#0f172a");
    inner.setAttribute("rx", "2");
    
    svg.appendChild(outer);
    svg.appendChild(inner);
}

// Verifier Rule Selection
function setVerifyRule(rule) {
    state.activeRule = rule;
    
    // Toggle active classes on buttons
    document.getElementById("rule-age").classList.remove("active");
    document.getElementById("rule-region").classList.remove("active");
    document.getElementById("rule-full").classList.remove("active");
    
    document.getElementById(`rule-${rule}`).classList.add("active");
    
    logTerminal(`Verificador configurado para regla: [${rule.toUpperCase()}]`, COLORS.info);
}

// Start Verification Scan via Backend API
function startVerificationScan() {
    if (!state.currentUser) {
        alert(window.getT("alert_mint_first"));
        return;
    }
    
    if (!state.walletUnlocked) {
        logTerminal("[ERR] Código QR inaccesible. Billetera móvil bloqueada.", COLORS.error);
        alert("Por favor desbloquee la Billetera Móvil (Sección 3) antes de escanear.");
        return;
    }
    
    logTerminal("Iniciando escaneo óptico de QR Dinámico...", COLORS.system);
    
    const user = state.currentUser;
    const rule = state.activeRule;
    
    setTimeout(async () => {
        logTerminal("QR escaneado exitosamente.", COLORS.ok);
        logTerminal("Enviando petición ZKP / SD al backend de verificación...", COLORS.system);
        
        let data;
        try {
            const response = await fetch("http://localhost:3000/api/v1/identities/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    sdjwt: user.rawCredential.jwt,
                    releasedDisclosures: user.rawCredential.disclosures,
                    rule: rule,
                    // Simulate a challenge signature
                    verificationChallenge: "challenge-123",
                    holderSignature: "dummy-signature"
                })
            });
            
            data = await response.json();
        } catch (e) {
            logTerminal(`[SISTEMA] Backend no detectado. Simulando verificación ZKP localmente...`, COLORS.warn);
            let approved = false;
            let disclosedClaims = {};
            if (rule === 'age') {
                const age = calculateAge(user.dob);
                approved = age >= 18;
            } else if (rule === 'region') {
                approved = user.region.toLowerCase().includes('managua');
            } else {
                approved = true;
                disclosedClaims = { dob: user.dob, region: user.region };
            }

            data = {
                success: true,
                approved: approved,
                logs: ["[OK] Validación criptográfica simulada exitosamente.", `[OK] Regla ZKP '${rule}' procesada.`],
                disclosedClaims: disclosedClaims,
                error: approved ? null : "El atributo no cumple la política requerida."
            };
        }
            
        // Print backend logs to terminal
            if (data.logs && Array.isArray(data.logs)) {
                data.logs.forEach(msg => {
                    const colorClass = msg.includes("[ERR]") ? COLORS.error 
                                     : msg.includes("[WARN]") ? COLORS.warn 
                                     : msg.includes("exitosamente") ? COLORS.ok 
                                     : COLORS.system;
                    logTerminal(msg, colorClass);
                });
            }
            
            // Render UI based on results and disclosed claims
            renderVerificationUI(data, rule, user);
            
            if (data.success && data.approved) {
                showVerificationResult(true, "REGLA CUMPLIDA Y VERIFICADA");
            } else {
                showVerificationResult(false, data.error || "VERIFICACIÓN RECHAZADA");
            }
        } catch (err) {
            logTerminal(`[ERR] Error de conexión con backend: ${err.message}`, COLORS.error);
            showVerificationResult(false, "Error de Red");
        }
    }, 1000);
}

// Function to update the ZKP visual UI after backend response
function renderVerificationUI(data, rule, user) {
    const reqBadge = document.getElementById("verify-disclosed-req");
    const proofText = document.getElementById("verify-disclosed-proof");
    const rowDob = document.getElementById("row-raw-dob");
    const rowRegion = document.getElementById("row-raw-region");
    const disclosedDob = document.getElementById("verify-disclosed-dob");
    const disclosedRegion = document.getElementById("verify-disclosed-region");
    
    rowDob.classList.remove("hidden");
    rowRegion.classList.remove("hidden");
    disclosedDob.classList.add("redact-text");
    disclosedRegion.classList.add("redact-text");
    
    if (rule === 'age') {
        reqBadge.innerText = "ZKP Mayor de 18 Años";
        proofText.innerText = "Backend Lattice-based Range Proof Verified";
        disclosedDob.innerText = "[OCULTO - PROBADO POR ZKP]";
        disclosedRegion.innerText = "[OCULTO - NO SOLICITADO]";
    } else if (rule === 'region') {
        reqBadge.innerText = "ZKP Residencia Managua";
        proofText.innerText = "Backend Lattice-based Set Membership Proof Verified";
        disclosedDob.innerText = "[OCULTO - NO SOLICITADO]";
        disclosedRegion.innerText = "[OCULTO - PROBADO POR ZKP]";
    } else {
        reqBadge.innerText = "Revelación Selectiva Completa";
        proofText.innerText = "Backend SD-JWT Full Attribute Signature Verified";
        
        if (data.disclosedClaims) {
            disclosedDob.innerText = data.disclosedClaims.dob || "[OCULTO]";
            disclosedRegion.innerText = data.disclosedClaims.region || "[OCULTO]";
            if (data.disclosedClaims.dob) disclosedDob.classList.remove("redact-text");
            if (data.disclosedClaims.region) disclosedRegion.classList.remove("redact-text");
        }
    }
}

// Display verification result
function showVerificationResult(success, text) {
    const box = document.getElementById("verify-result-box");
    const banner = document.getElementById("verify-banner");
    const bannerText = document.getElementById("verify-banner-text");
    
    box.classList.remove("hidden");
    
    if (success) {
        banner.className = "result-status-banner success";
        bannerText.innerText = `APROBADO: ${text}`;
        logTerminal(`[ACCESO] ACCESO AUTORIZADO - REGLA CUMPLIDA.`, COLORS.ok);
    } else {
        banner.className = "result-status-banner failed";
        bannerText.innerText = `DENEGADO: ${text}`;
        logTerminal(`[ACCESO] ACCESO RECHAZADO - VERIFICACIÓN FALLIDA.`, COLORS.error);
    }
}

// -----------------------------------------------------
// Export Functionality (JPG and PDF)
// -----------------------------------------------------

async function downloadCardAsJPG() {
    if (!state.currentUser) {
        alert("Primero debe acuñar una credencial.");
        return;
    }
    const cardElement = document.querySelector(".virtual-card");
    if (!cardElement) return;

    try {
        const canvas = await window.html2canvas(cardElement, {
            scale: 2, 
            backgroundColor: "#131422"
        });
        
        const image = canvas.toDataURL("image/jpeg", 1.0);
        const link = document.createElement("a");
        link.download = `OmniID_Cedula_${state.currentUser.omniID}.jpg`;
        link.href = image;
        link.click();
    } catch (e) {
        console.error("Error generating JPG:", e);
        alert("Error al generar la imagen.");
    }
}

async function downloadRegistrationPDF() {
    if (!state.currentUser) {
        alert("Primero debe acuñar una credencial.");
        return;
    }
    
    try {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF({
            orientation: "portrait",
            unit: "mm",
            format: "a4"
        });
        
        // Draw a simple "Planet" Logo
        // Dark blue circle
        doc.setFillColor(30, 60, 120);
        doc.circle(105, 30, 12, 'F');
        // Cyan rings
        doc.setDrawColor(50, 200, 255);
        doc.setLineWidth(1.5);
        doc.ellipse(105, 30, 18, 5, 'D');
        doc.ellipse(105, 30, 22, 7, 'D');

        // Header Texts
        const t = translations[window.currentLang] || translations['es'];
        doc.setFont("helvetica", "bold");
        doc.setFontSize(16);
        doc.setTextColor(20, 20, 40);
        doc.text(t.pdf_header, 105, 55, { align: "center" });
        
        doc.setFontSize(12);
        doc.setTextColor(80, 80, 100);
        doc.text("CONSTANCIA FISCAL Y REGISTRO DE IDENTIDAD", 105, 62, { align: "center" });
        
        doc.setDrawColor(200, 200, 200);
        doc.setLineWidth(0.5);
        doc.line(20, 70, 190, 70);
        
        // Info text
        doc.setFont("helvetica", "normal");
        doc.setFontSize(10);
        doc.setTextColor(50, 50, 50);
        doc.text(`${t.pdf_issue}:`, 40, 75);
        doc.text(state.currentUser.issueDate, 90, 75);
        
        doc.text(`${t.pdf_fiscal}:`, 40, 85);
        doc.text(state.currentUser.omniID, 90, 85);
        
        doc.text(`${t.pdf_doc}:`, 40, 95);
        doc.text(state.currentUser.nationalId, 90, 95);
        doc.setFont("helvetica", "italic");
        doc.text(t.pdf_desc1, 105, 110, { align: "center" });
        doc.text(t.pdf_desc2, 105, 117, { align: "center" });     
        // Capture the virtual card
        const cardElement = document.querySelector(".virtual-card");
        const canvas = await window.html2canvas(cardElement, { scale: 2, backgroundColor: "#131422" });
        const imgData = canvas.toDataURL("image/jpeg", 1.0);
        
        // Center the card on A4 (A4 width is 210mm)
        const imgWidth = 110; 
        const imgHeight = (canvas.height * imgWidth) / canvas.width;
        const xOffset = (210 - imgWidth) / 2;
        
        // Draw a subtle border frame for the ID
        doc.setDrawColor(180, 180, 190);
        doc.setLineWidth(0.3);
        doc.rect(xOffset - 1, 125 - 1, imgWidth + 2, imgHeight + 2);

        // Add image to PDF
        doc.addImage(imgData, 'JPEG', xOffset, 125, imgWidth, imgHeight);
        
        // Footer / Signatures
        const bottomY = 125 + imgHeight + 20;
        doc.line(20, bottomY, 190, bottomY);
        
        doc.setFontSize(9);
        doc.setTextColor(100, 100, 110);
        doc.text(t.pdf_footer1, 105, 275, { align: "center" });
        
        doc.setFontSize(8);
        doc.text(state.currentUser.issuerSig.substring(0, 40) + "...", 105, 280, { align: "center" });
        
        doc.setFontSize(10);
        doc.setFont("helvetica", "bold");
        doc.text(t.pdf_footer2, 105, 288, { align: "center" });
        
        // Save
        doc.save(`Registro_Fiscal_${state.currentUser.omniID}.pdf`);
    } catch (e) {
        console.error("Error generating PDF:", e);
        alert("Error al generar el PDF.");
    }
}

