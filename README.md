# 🛡️ OmniID: Sovereign, Post-Quantum, and Decentralized Identity System

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0.html)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20.0.0-emerald.svg)](https://nodejs.org/)
[![NIST PQC Compliant](https://img.shields.io/badge/NIST_PQC-FIPS_203_%2F_204-blue.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![W3C DID Compliant](https://img.shields.io/badge/W3C_DID-v1.0-orange.svg)](https://www.w3.org/TR/did-core/)

**OmniID** es un ecosistema técnico de Identidad Digital Soberana (SSI) de grado gubernamental diseñado para ser inmune a la falsificación, la suplantación de identidad y futuros ataques mediante computadoras cuánticas. El sistema integra Tecnología de Registro Distribuido (DLT), criptografía basada en redes de celosías (Lattice-based Cryptography), mecanismos de divulgación selectiva (SD-JWT), bases de datos en la nube (Supabase/PostgreSQL) y autenticación WebAuthn (FIDO2) para garantizar un balance perfecto entre seguridad estatal y el control total del usuario sobre sus datos.

---

## 🏛️ Arquitectura del Sistema (Híbrida)

OmniID se estructura bajo un modelo híbrido avanzado que combina la **Identidad Soberana (SSI)** con bases de datos relacionales robustas para la auditoría y gestión de emisiones.

```mermaid
graph TD
    subgraph Emisor (Gobierno/Entidad de Confianza)
        Issuer["Servicio Emisor OmniID (Node.js)"]
        DB[(Supabase / PostgreSQL)]
        KYC["Motor de Verificación KYC y Biometría"]
        HSM["Hardware Security Module (PQC ML-DSA-85)"]
    end

    subgraph Propietario (Usuario)
        Wallet["Billetera Móvil Local (Mobile ID Wallet)"]
        Enclave["WebAuthn / FIDO2 (TouchID/Windows Hello)"]
    end

    subgraph Red DLT / Ledger Indy
        Registry["Registro Público de DIDs y Esquemas"]
    end

    subgraph Verificador (Entidad Externa)
        Verifier["Aplicación / Terminal Verificadora (ZKP)"]
    end

    %% Relaciones
    KYC -->|1. Valida Datos y Biometría| Issuer
    Issuer -->|2. Registra Emisión Oficial| DB
    Issuer -->|3. Emite Credencial Firmada (SD-JWT)| Wallet
    Wallet -->|4. Bloqueo Biométrico FIDO2| Enclave
    Wallet -->|5. Presentación Verificable (ZKP)| Verifier
    Verifier -->|6. Consulta Claves PQC| Registry
    Issuer -->|7. Registra Clave Pública DID| Registry
```

---

## ✨ Características y Funcionalidades Principales

### 1. Interfaz de Usuario Multilingüe (i18n)
La plataforma ha sido internacionalizada soportando **8 de los idiomas principales** del mundo, con cambio de idioma en tiempo real (sin recargar la página):
*   Español (ES), Inglés (EN), Francés (FR), Mandarín (ZH), Árabe (AR - *Soporte RTL*), Ruso (RU), Portugués (PT) y Alemán (DE).

### 2. Autenticación Biométrica Real (WebAuthn / FIDO2)
El sistema ha dejado atrás las simulaciones para integrar la API nativa de **WebAuthn**. Permite escanear biometría real utilizando los sensores de hardware del dispositivo del usuario (Windows Hello, Touch ID, Face ID o llaves YubiKey) para atestar su identidad resistente al phishing.

### 3. Portal KYC y Cédula Virtual Ampliada
El formulario de emisión (Panel 1) y la Cédula Virtual (Panel 2) capturan y cifran datos expandidos:
*   **Nombre Completo, Fecha de Nacimiento (ISO), Dirección.**
*   **Documento de Origen (DNI / Pasaporte).**
*   **Nacionalidad y Género.**

### 4. Exportación Oficial y Constancias Fiscales
Los usuarios pueden materializar su identidad digital a través de exportaciones de alta resolución:
*   **Descarga JPG**: Captura visual de la tarjeta 3D de la "Naciones Unidas del Mundo" con todas las firmas PQC visibles.
*   **Descarga PDF**: Generación de un Documento Fiscal formal, enmarcado y con el membrete traducido al idioma seleccionado, ideal para trámites físicos.

---

## 🛠️ Especificaciones Técnicas y Criptográficas

| Módulo | Estándar / Algoritmo | Implementación en OmniID | Cumplimiento |
| :--- | :--- | :--- | :--- |
| **Identificadores** | W3C DID | `did:omni:<Unique-ID>` | W3C DID v1.0 |
| **Cifrado FPE** | FF1 (Feistel Network) | Mapeo determinista de 15 caracteres | NIST SP 800-38G |
| **Firmas Digitales** | ML-DSA-65 / ML-DSA-85 | Firmas basadas en celosías (CRYSTALS) | NIST FIPS 204 |
| **Privacidad / ZKP** | SD-JWT | Divulgación selectiva de atributos KYC | IETF SD-JWT Spec |
| **Base de Datos** | PostgreSQL (Supabase) | Auditoría relacional centralizada | ISO 27001 |
| **Biometría Segura** | WebAuthn + Fuzzy BCH | Cero almacenamiento de biometría cruda en DB | FIDO2 / W3C |
| **Cumplimiento GDPR**| Arquitectura de 5 Pilares | Encriptación en reposo, 0 vulnerabilidades NPM | GDPR Art. 15-32 |

---

## 📂 Estructura del Repositorio

```
├── index.html              # Interfaz gráfica del Simulador Web (Cédula Virtual)
├── styles.css              # Estilos UI (Glassmorphism, Dark Theme, PDF Exports)
├── app.js                  # Lógica frontend (WebAuthn, Exportación PDF/JPG)
├── translations.js         # Diccionario i18n para los 8 idiomas soportados
├── update-html.js          # Script utilitario de migración DOM
├── README.md               # Documentación general del sistema
└── backend/                # Servidor API REST (Criptografía Real)
    ├── .env                # Variables de entorno (Supabase Keys, Ports)
    ├── package.json        # Gestión de dependencias (Vulnerabilidades Parcheadas)
    └── src/
        ├── server.ts       # Servidor Express, CORS configurado, Middlewares
        ├── services/
        │   └── supabaseClient.ts # Conexión a Base de Datos PostgreSQL
        ├── crypto/
        │   ├── fpe.ts      # Generador de IDs FPE (Hull-Dobell LCG)
        │   └── pqc.ts      # Firmas ML-DSA, Fuzzy BCH y SD-JWT
        ├── routes/
        │   └── identity.ts # API endpoints de enrolamiento con Supabase Insert
        └── test_flow.ts    # Script de pruebas automatizadas
```

---

## 🚀 Guía de Instalación y Ejecución

### Requisitos Previos
*   [Node.js](https://nodejs.org/) v20.0.0 o superior instalado.
*   Una cuenta en [Supabase](https://supabase.com/) (Para la base de datos PostgreSQL).

### Paso 1: Configurar la Base de Datos (Supabase)
Cree un nuevo proyecto en Supabase, diríjase al **SQL Editor** y ejecute el siguiente comando para crear la tabla de auditoría:

```sql
create table issued_identities (
  id uuid default gen_random_uuid() primary key,
  omni_id text not null unique,
  did text not null,
  full_name text not null,
  national_id text,
  nationality text,
  gender text,
  dob date,
  region text,
  bio_hash text not null,
  issuer_sig text not null,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null
);
```

### Paso 2: Configurar el Servidor Backend
Navegue al directorio del servidor e instale las dependencias seguras:

```bash
cd backend
npm install
```

Configure sus variables de entorno editando el archivo `backend/.env`:
```env
SUPABASE_URL=https://<tu-id>.supabase.co
SUPABASE_SERVICE_KEY=eyJhbGciOi...
```

### Paso 3: Levantar la API
Inicie el servidor en modo desarrollo (con recarga automática):

```bash
npm run dev
```

El servidor comenzará a escuchar en: `http://localhost:3000`.

### Paso 4: Ejecutar el Frontend
Utilice un servidor local rápido para evitar bloqueos de CORS en el frontend. Si tiene Node.js:

```bash
npx http-server -p 8080
```
Y abra `http://localhost:8080` en su navegador.

---

## 📡 Referencia de la API (Endpoints)

### 1. Emisión de Cédulas Digitales (Enrolamiento)
*   **Ruta**: `POST /api/v1/identities/issue`
*   **Descripción**: Procesa los datos KYC, genera firmas PQC, inserta el registro en Supabase y devuelve las llaves al usuario.
*   **Cuerpo (JSON)**:
    ```json
    {
      "fullName": "Joaquin Obando",
      "dob": "2000-05-15",
      "region": "Managua, Nicaragua",
      "nationalId": "001-123456-0000A",
      "nationality": "Nicaragüense",
      "gender": "M",
      "biometricTemplate": [142, 99, 44, 212, 85, 12, 190, 77]
    }
    ```

### 2. Verificación de Identidad (Auditoría ZKP)
*   **Ruta**: `POST /api/v1/identities/verify`
*   **Descripción**: Valida el Token SD-JWT y procesa las reglas de conocimiento cero (Zero-Knowledge Proofs).

---

## 🗺️ Plan de Continuidad y Próximas Fases

1.  **Persistencia Local de Identidad**: Implementar `localStorage` o `IndexedDB` en el frontend para simular el resguardo permanente de la billetera. De este modo, al recargar la página el usuario iniciaría sesión validando su biometría en lugar de volver a registrarse.
2.  **Ledger Distribuido Real**: Integrar un nodo validador Hyperledger Indy para publicar efectivamente los DIDs.
3.  **App Móvil Nativa**: Desarrollar la aplicación compañera en React Native atada al Secure Enclave de Android/iOS.

---

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia GNU Affero General Public License v3.0 (AGPL-3.0). Consulte el archivo [LICENSE](LICENSE) para más detalles.
