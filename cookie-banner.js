/**
 * OmniID GDPR — Cookie Consent Banner
 * 
 * Glassmorphism-styled cookie consent banner that integrates with
 * the OmniID visual design language. Supports granular consent
 * for Essential, Functional, and Analytics cookies.
 * 
 * GDPR/ePrivacy compliant cookie consent implementation.
 */

(function() {
    'use strict';

    const CONSENT_COOKIE_NAME = 'omniid_consent';
    const CONSENT_VERSION = '1.0';

    // ─── Check if consent already given ──────────────────────────────────────

    function getStoredConsent() {
        try {
            const stored = localStorage.getItem(CONSENT_COOKIE_NAME);
            if (stored) return JSON.parse(stored);
        } catch (e) { /* ignore */ }
        return null;
    }

    function storeConsent(preferences) {
        const data = {
            version: CONSENT_VERSION,
            timestamp: new Date().toISOString(),
            essential: true,
            functional: !!preferences.functional,
            analytics: !!preferences.analytics
        };
        localStorage.setItem(CONSENT_COOKIE_NAME, JSON.stringify(data));
        
        // Also set as a cookie for server-side reading
        const expires = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toUTCString();
        document.cookie = `${CONSENT_COOKIE_NAME}=${encodeURIComponent(JSON.stringify(data))}; expires=${expires}; path=/; SameSite=Lax; Secure`;
    }

    // ─── Don't show if already consented ─────────────────────────────────────

    const existing = getStoredConsent();
    if (existing && existing.version === CONSENT_VERSION) return;

    // ─── Inject Styles ───────────────────────────────────────────────────────

    const style = document.createElement('style');
    style.textContent = `
        .omniid-cookie-overlay {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            z-index: 10000;
            padding: 0 24px 24px;
            pointer-events: none;
            animation: cookieSlideUp 0.5s ease-out;
        }

        @keyframes cookieSlideUp {
            from { transform: translateY(100%); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .omniid-cookie-banner {
            pointer-events: all;
            max-width: 720px;
            margin: 0 auto;
            background: rgba(15, 23, 42, 0.85);
            backdrop-filter: blur(20px) saturate(180%);
            -webkit-backdrop-filter: blur(20px) saturate(180%);
            border: 1px solid rgba(139, 92, 246, 0.25);
            border-radius: 20px;
            padding: 28px 32px;
            box-shadow: 
                0 -8px 32px rgba(139, 92, 246, 0.15),
                0 4px 24px rgba(0, 0, 0, 0.4),
                inset 0 1px 0 rgba(255, 255, 255, 0.05);
            font-family: 'Outfit', sans-serif;
            color: #e2e8f0;
        }

        .omniid-cookie-banner .cookie-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 14px;
        }

        .omniid-cookie-banner .cookie-header svg {
            width: 28px;
            height: 28px;
            flex-shrink: 0;
        }

        .omniid-cookie-banner .cookie-header h3 {
            margin: 0;
            font-size: 16px;
            font-weight: 600;
            background: linear-gradient(135deg, #8b5cf6, #10b981);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .omniid-cookie-banner .cookie-description {
            font-size: 13px;
            color: #94a3b8;
            line-height: 1.55;
            margin-bottom: 18px;
        }

        .omniid-cookie-banner .cookie-description a {
            color: #8b5cf6;
            text-decoration: none;
        }

        .omniid-cookie-banner .cookie-description a:hover {
            text-decoration: underline;
        }

        .omniid-cookie-options {
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin-bottom: 20px;
        }

        .omniid-cookie-option {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 14px;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255, 255, 255, 0.06);
            transition: border-color 0.2s;
        }

        .omniid-cookie-option:hover {
            border-color: rgba(139, 92, 246, 0.3);
        }

        .omniid-cookie-option .option-info {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }

        .omniid-cookie-option .option-name {
            font-size: 13px;
            font-weight: 600;
            color: #e2e8f0;
        }

        .omniid-cookie-option .option-desc {
            font-size: 11px;
            color: #64748b;
        }

        .omniid-cookie-option .option-badge {
            font-size: 10px;
            padding: 3px 8px;
            border-radius: 6px;
            background: rgba(16, 185, 129, 0.15);
            color: #10b981;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        /* Toggle Switch */
        .cookie-toggle {
            position: relative;
            width: 40px;
            height: 22px;
            flex-shrink: 0;
        }

        .cookie-toggle input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .cookie-toggle .slider {
            position: absolute;
            cursor: pointer;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 22px;
            transition: 0.3s;
        }

        .cookie-toggle .slider::before {
            content: '';
            position: absolute;
            height: 16px;
            width: 16px;
            left: 3px;
            bottom: 3px;
            background: #94a3b8;
            border-radius: 50%;
            transition: 0.3s;
        }

        .cookie-toggle input:checked + .slider {
            background: linear-gradient(135deg, #8b5cf6, #6366f1);
        }

        .cookie-toggle input:checked + .slider::before {
            transform: translateX(18px);
            background: white;
        }

        .cookie-toggle input:disabled + .slider {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .omniid-cookie-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .omniid-cookie-actions button {
            padding: 10px 20px;
            border: none;
            border-radius: 10px;
            font-family: 'Outfit', sans-serif;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.25s;
            flex: 1;
            min-width: 140px;
        }

        .btn-accept-all {
            background: linear-gradient(135deg, #8b5cf6, #6366f1);
            color: white;
            box-shadow: 0 4px 15px rgba(139, 92, 246, 0.3);
        }

        .btn-accept-all:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(139, 92, 246, 0.4);
        }

        .btn-essential-only {
            background: rgba(255, 255, 255, 0.08);
            color: #e2e8f0;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
        }

        .btn-essential-only:hover {
            background: rgba(255, 255, 255, 0.12);
        }

        .btn-save-preferences {
            background: rgba(16, 185, 129, 0.15);
            color: #10b981;
            border: 1px solid rgba(16, 185, 129, 0.3) !important;
        }

        .btn-save-preferences:hover {
            background: rgba(16, 185, 129, 0.25);
        }

        .omniid-cookie-details-toggle {
            background: none;
            border: none;
            color: #8b5cf6;
            font-size: 12px;
            cursor: pointer;
            padding: 0;
            margin-bottom: 10px;
            font-family: 'Outfit', sans-serif;
        }

        .omniid-cookie-details-toggle:hover {
            text-decoration: underline;
        }

        @media (max-width: 600px) {
            .omniid-cookie-overlay { padding: 0 12px 12px; }
            .omniid-cookie-banner { padding: 20px; }
            .omniid-cookie-actions { flex-direction: column; }
            .omniid-cookie-actions button { min-width: auto; }
        }
    `;
    document.head.appendChild(style);

    // ─── Create Banner HTML ──────────────────────────────────────────────────

    const overlay = document.createElement('div');
    overlay.className = 'omniid-cookie-overlay';
    overlay.id = 'omniid-cookie-overlay';
    overlay.innerHTML = `
        <div class="omniid-cookie-banner" role="dialog" aria-label="Cookie Consent">
            <div class="cookie-header">
                <svg viewBox="0 0 24 24" fill="none" stroke="url(#cookie-grad)" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <defs>
                        <linearGradient id="cookie-grad" x1="4" y1="2" x2="20" y2="22">
                            <stop stop-color="#8b5cf6"/>
                            <stop offset="1" stop-color="#10b981"/>
                        </linearGradient>
                    </defs>
                </svg>
                <h3>Privacidad y Cookies — OmniID</h3>
            </div>

            <p class="cookie-description">
                Utilizamos cookies estrictamente necesarias para el funcionamiento del sistema de identidad.
                Las cookies opcionales nos ayudan a mejorar su experiencia.
                <a href="#" id="cookie-policy-link">Política de cookies</a>.
            </p>

            <button class="omniid-cookie-details-toggle" id="cookie-toggle-details">
                ▸ Personalizar preferencias
            </button>

            <div class="omniid-cookie-options" id="cookie-options" style="display: none;">
                <div class="omniid-cookie-option">
                    <div class="option-info">
                        <span class="option-name">🔒 Estrictamente Necesarias</span>
                        <span class="option-desc">Sesión, CSRF, consentimiento. No se pueden desactivar.</span>
                    </div>
                    <span class="option-badge">SIEMPRE ACTIVAS</span>
                </div>
                <div class="omniid-cookie-option">
                    <div class="option-info">
                        <span class="option-name">⚙️ Funcionales</span>
                        <span class="option-desc">Preferencias de idioma y tema visual.</span>
                    </div>
                    <label class="cookie-toggle">
                        <input type="checkbox" id="consent-functional" checked>
                        <span class="slider"></span>
                    </label>
                </div>
                <div class="omniid-cookie-option">
                    <div class="option-info">
                        <span class="option-name">📊 Analíticas</span>
                        <span class="option-desc">Estadísticas anónimas de uso del servicio.</span>
                    </div>
                    <label class="cookie-toggle">
                        <input type="checkbox" id="consent-analytics">
                        <span class="slider"></span>
                    </label>
                </div>
            </div>

            <div class="omniid-cookie-actions">
                <button class="btn-accept-all" id="cookie-accept-all">Aceptar Todas</button>
                <button class="btn-essential-only" id="cookie-essential-only">Solo Esenciales</button>
                <button class="btn-save-preferences" id="cookie-save-prefs" style="display: none;">
                    Guardar Preferencias
                </button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    // ─── Event Handlers ──────────────────────────────────────────────────────

    function closeBanner() {
        const banner = document.getElementById('omniid-cookie-overlay');
        if (banner) {
            banner.style.animation = 'cookieSlideUp 0.3s ease-in reverse forwards';
            setTimeout(() => banner.remove(), 300);
        }
    }

    // Accept all
    document.getElementById('cookie-accept-all').addEventListener('click', function() {
        storeConsent({ functional: true, analytics: true });
        closeBanner();
    });

    // Essential only
    document.getElementById('cookie-essential-only').addEventListener('click', function() {
        storeConsent({ functional: false, analytics: false });
        closeBanner();
    });

    // Toggle details
    document.getElementById('cookie-toggle-details').addEventListener('click', function() {
        const options = document.getElementById('cookie-options');
        const saveBtn = document.getElementById('cookie-save-prefs');
        const isHidden = options.style.display === 'none';
        
        options.style.display = isHidden ? 'flex' : 'none';
        saveBtn.style.display = isHidden ? 'block' : 'none';
        this.textContent = isHidden ? '▾ Ocultar preferencias' : '▸ Personalizar preferencias';
    });

    // Save custom preferences
    document.getElementById('cookie-save-prefs').addEventListener('click', function() {
        storeConsent({
            functional: document.getElementById('consent-functional').checked,
            analytics: document.getElementById('consent-analytics').checked
        });
        closeBanner();
    });

})();
