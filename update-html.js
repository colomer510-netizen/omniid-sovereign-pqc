const fs = require('fs');
let html = fs.readFileSync('index.html', 'utf8');

// Header select
html = html.replace('<div class="network-badge">', `        <div class="lang-container" style="margin-right: 15px;">
            <select id="lang-selector" style="background: rgba(255,255,255,0.1); color: white; border: 1px solid #4a5568; border-radius: 4px; padding: 4px 8px; font-family: 'Outfit';">
                <option value="es">ES - Español</option>
                <option value="en">EN - English</option>
                <option value="fr">FR - Français</option>
                <option value="zh">ZH - 中文</option>
                <option value="ar">AR - العربية</option>
                <option value="ru">RU - Русский</option>
                <option value="pt">PT - Português</option>
                <option value="de">DE - Deutsch</option>
            </select>
        </div>
        <div class="network-badge">`);

// Add script
html = html.replace('<script src="app.js"></script>', '<script src="translations.js"></script>\n    <script src="app.js"></script>');

// IDs
html = html.replace('<h2>1. Portal de Emisión Nacional (KYC)</h2>', '<h2 id="panel-issuer-title">1. Portal de Emisión Nacional (KYC)</h2>');
html = html.replace('<p class="panel-desc">Enrolamiento biométrico y generación criptográfica FPE del identificador.</p>', '<p class="panel-desc" id="panel-issuer-desc">Enrolamiento biométrico y generación criptográfica FPE del identificador.</p>');
html = html.replace('<label for="input-fullname">Nombre Completo</label>', '<label for="input-fullname" id="lbl-fullname">Nombre Completo</label>');
html = html.replace('<label for="input-national-id">Documento de Identidad (DNI/Pasaporte)</label>', '<label for="input-national-id" id="lbl-national-id">Documento de Identidad (DNI/Pasaporte)</label>');
html = html.replace('<label for="input-nationality">Nacionalidad</label>', '<label for="input-nationality" id="lbl-nationality">Nacionalidad</label>');
html = html.replace('<label for="input-dob">Fecha Nacimiento</label>', '<label for="input-dob" id="lbl-dob">Fecha Nacimiento</label>');
html = html.replace('<label for="input-gender">Género</label>', '<label for="input-gender" id="lbl-gender">Género</label>');
html = html.replace('<label for="input-region">Dirección de Residencia</label>', '<label for="input-region" id="lbl-region">Dirección de Residencia</label>');

html = html.replace('<span>Escanear Biometría FIDO2 / Windows Hello</span>', '<span id="btn-scan-bio">Escanear Biometría FIDO2 / Windows Hello</span>');
html = html.replace('<span>Acuñar Credencial PQC</span>', '<span id="btn-issue-cred">Acuñar Credencial PQC</span>');

html = html.replace('<h2>2. Cédula Virtual (Portal Web)</h2>', '<h2 id="panel-virtual-title">2. Cédula Virtual (Portal Web)</h2>');
html = html.replace('<p class="panel-desc">Vista de la credencial digital en el portal web oficial del ciudadano.</p>', '<p class="panel-desc" id="panel-virtual-desc">Vista de la credencial digital en el portal web oficial del ciudadano.</p>');
html = html.replace('<div class="gov-title">REPUBLICA DE OMNILANDIA</div>', '<div class="gov-title" id="gov-title">REPUBLICA DE OMNILANDIA</div>');
html = html.replace('<div class="gov-subtitle">DOCUMENTO NACIONAL DE IDENTIDAD DIGITAL</div>', '<div class="gov-subtitle" id="gov-subtitle">DOCUMENTO NACIONAL DE IDENTIDAD DIGITAL</div>');

html = html.replace('<span class="lbl">Apellidos y Nombres</span>', '<span class="lbl" id="lbl-card-fullname">Apellidos y Nombres</span>');
html = html.replace('<span class="lbl">ID Origen (DNI)</span>', '<span class="lbl" id="lbl-card-national-id">ID Origen (DNI)</span>');
html = html.replace('<span class="lbl">Nacionalidad</span>', '<span class="lbl" id="lbl-card-nationality">Nacionalidad</span>');
html = html.replace('<span class="lbl">Fecha Nac. (ISO)</span>', '<span class="lbl" id="lbl-card-dob">Fecha Nac. (ISO)</span>');
html = html.replace('<span class="lbl">Género</span>', '<span class="lbl" id="lbl-card-gender">Género</span>');
html = html.replace('<span class="lbl">OmniID Soberano</span>', '<span class="lbl" id="lbl-card-omniid">OmniID Soberano</span>');
html = html.replace('<span class="lbl">Emisión</span>', '<span class="lbl" id="lbl-card-issue">Emisión</span>');
html = html.replace('<span class="lbl">Expiración</span>', '<span class="lbl" id="lbl-card-expiry">Expiración</span>');
html = html.replace('<span class="lbl">Biometría Hasheada (Fuzzy BCH Cryptographic Commitment)</span>', '<span class="lbl" id="lbl-card-bio-hash">Biometría Hasheada (Fuzzy BCH Cryptographic Commitment)</span>');
html = html.replace('<span class="lbl">Firma Digital del Emisor (PQC ML-DSA-85)</span>', '<span class="lbl" id="lbl-card-issuer-sig">Firma Digital del Emisor (PQC ML-DSA-85)</span>');

html = html.replace('🖼️ Descargar JPG (Cédula)', '<span id="btn-dl-jpg">🖼️ Descargar JPG (Cédula)</span>');
html = html.replace('📄 Descargar PDF (Registro Fiscal)', '<span id="btn-dl-pdf">📄 Descargar PDF (Registro Fiscal)</span>');

html = html.replace('<h2>3. Módulo Verificador (Relying Party)</h2>', '<h2 id="panel-verifier-title">3. Módulo Verificador (Relying Party)</h2>');
html = html.replace('<p class="panel-desc">Verificación Zero-Knowledge Proof (ZKP) sin revelar datos innecesarios.</p>', '<p class="panel-desc" id="panel-verifier-desc">Verificación Zero-Knowledge Proof (ZKP) sin revelar datos innecesarios.</p>');

html = html.replace('<span class="label-features">Política de Divulgación ZKP:</span>', '<span class="label-features" id="lbl-zkp-policy">Política de Divulgación ZKP:</span>');
html = html.replace('<span class="rule-title">Mayor de 18 Años</span>', '<span class="rule-title" id="rule-age-title">Mayor de 18 Años</span>');
html = html.replace('<span class="rule-subtitle">ZKP Range Proof</span>', '<span class="rule-subtitle" id="rule-age-sub">ZKP Range Proof</span>');
html = html.replace('<span class="rule-title">¿Residente en Managua?</span>', '<span class="rule-title" id="rule-region-title">¿Residente en Managua?</span>');
html = html.replace('<span class="rule-subtitle">ZKP de Atributo de Residencia</span>', '<span class="rule-subtitle" id="rule-region-sub">ZKP de Atributo de Residencia</span>');
html = html.replace('<span class="rule-title">Identidad Completa</span>', '<span class="rule-title" id="rule-full-title">Identidad Completa</span>');
html = html.replace('<span class="rule-subtitle">Revelación Selectiva Completa</span>', '<span class="rule-subtitle" id="rule-full-sub">Revelación Selectiva Completa</span>');

html = html.replace('<span>Escanear QR Dinámico y Validar en Ledger</span>', '<span id="btn-scan-qr">Escanear QR Dinámico y Validar en Ledger</span>');
html = html.replace('<span>Consola de Auditoría de Seguridad (Zero Trust)</span>', '<span id="term-title">Consola de Auditoría de Seguridad (Zero Trust)</span>');

fs.writeFileSync('index.html', html);
console.log("HTML successfully updated with IDs for i18n.");
