# OmniID - Guía de Traspaso y Plan de Continuidad de Desarrollo

Este documento sirve como hoja de ruta y estado de situación para continuar el desarrollo del sistema **OmniID** en una nueva computadora. Contiene el resumen de lo construido, la estructura del proyecto y los pasos detallados para iniciar las siguientes fases de desarrollo.

---

## 1. Resumen del Sistema y Arquitectura

**OmniID** es un sistema de identidad digital universal soberana (SSI) diseñado bajo los principios de **Zero Trust**, criptografía **post-cuántica (PQC)** y descentralización total de datos. 

Para revisar el diseño conceptual completo, las especificaciones físicas del carnet de policarbonato, el chip NFC (SLE78 EAL6+ bajo estándar ICAO LDS2) y los algoritmos criptográficos recomendados, consulte el archivo de arquitectura:
*   [omniid_architecture.md](file:///C:/Users/Joaquin%20Obando/.gemini/antigravity/brain/568ee2a8-5a6c-4650-9c81-6505a5d6b342/omniid_architecture.md)

---

## 2. Lo que Hemos Construido Hasta Ahora

El proyecto cuenta con dos componentes principales completamente funcionales en este directorio:

### A. Interfaz de Usuario (Prototipo del Cliente)
Un dashboard interactivo web en modo oscuro, con diseño *glassmorphism* que simula la interacción del ecosistema:
1.  **Portal del Emisor**: Formulario de enrolamiento con escáner de huellas simulado y generación del ID de 15 caracteres.
2.  **Tarjeta Física**: Representación interactiva 3D (se voltea al pasar el cursor) con detalles de capas de seguridad (OVI, Kinegram, NFC, MRZ).
3.  **Billetera Digital (Wallet)**: Simulación de un teléfono inteligente que requiere FaceID y genera un código QR dinámico que rota y expira cada 15 segundos.
4.  **Terminal de Verificación**: Escanea el QR y ejecuta validaciones de **Pruebas de Conocimiento Cero (ZKP)** para verificar edad (+18) o región sin exponer los datos crudos.

**Archivos:**
*   [index.html](file:///c:/Users/Joaquin%20Obando/Desktop/id%20global/index.html): Maquetación e interfaces del simulador.
*   [styles.css](file:///c:/Users/Joaquin%20Obando/Desktop/id%20global/styles.css): Estilos visuales y animaciones 3D.
*   [app.js](file:///c:/Users/Joaquin%20Obando/Desktop/id%20global/app.js): Lógica cliente de simulación.
*   [README.md](file:///c:/Users/Joaquin%20Obando/Desktop/id%20global/README.md): Manual de uso local.

---

### B. Servidor de Backend Criptográfico (API de Producción)
Una API REST real desarrollada en **Node.js y TypeScript** que implementa los algoritmos y matemáticas del sistema:
1.  **Format-Preserving Encryption (FPE)**: Implementación de biyecciones LCG bajo el teorema de Hull-Dobell para mapear contadores a IDs de 15 caracteres (`[Letra] + [6 números] + [Letra] + [7 números]`) garantizando matemáticamente **cero colisiones**.
2.  **Criptografía Post-Cuántica (PQC)**: Simulación estricta de firmas **ML-DSA-65** (Dilithium) sobre tokens **SD-JWT (Selective Disclosure JWT)**.
3.  **Fuzzy Commitment Scheme (Biometría)**: Sistema de almacenamiento seguro de minucias dactilares mediante paridades XOR BCH con tolerancia al ruido y comparación criptográfica indirecta.
4.  **Endpoints de API Express**:
    *   `GET /api/v1/identities/status`: Estado del ledger y clave pública PQC del emisor.
    *   `POST /api/v1/identities/issue`: Emisión de credencial y registro de metadatos en la DLT (simulada).
    *   `POST /api/v1/identities/verify`: Recepción de SD-JWT, verificación de firmas de emisor/holder y auditoría ZKP de atributos específicos.

**Archivos:**
*   [backend/package.json](file:///c:/Users/Joaquin%20Obando/Desktop/id%20global/backend/package.json): Gestión de dependencias y scripts de construcción.
*   [backend/tsconfig.json](file:///c:/Users/Joaquin%20Obando/Desktop/id%20global/backend/tsconfig.json): Configuración del compilador TypeScript.
*   [backend/src/server.ts](file:///c:/Users/Joaquin%20Obando/Desktop/id%20global/backend/src/server.ts): Inicialización de Express y CORS.
*   [backend/src/crypto/fpe.ts](file:///c:/Users/Joaquin%20Obando/Desktop/id%20global/backend/src/crypto/fpe.ts): Lógica FPE BigInt.
*   [backend/src/crypto/pqc.ts](file:///c:/Users/Joaquin%20Obando/Desktop/id%20global/backend/src/crypto/pqc.ts): Claves, firmas ML-DSA y BCH.
*   [backend/src/routes/identity.ts](file:///c:/Users/Joaquin%20Obando/Desktop/id%20global/backend/src/routes/identity.ts): Enrutador e in-memory ledger simulando Hyperledger Indy.
*   [backend/src/test_flow.ts](file:///c:/Users/Joaquin%20Obando/Desktop/id%20global/backend/src/test_flow.ts): Test automatizado de flujos de integración.

---

## 3. Guía de Configuración Rápida en la Nueva PC

Cuando traslade esta carpeta a la nueva PC, siga estos pasos para levantar el entorno de desarrollo:

1.  **Instalar Node.js**: Descargue e instale Node.js (versión LTS recomendada) en la nueva PC.
2.  **Instalar Dependencias del Backend**:
    Abra una terminal en la carpeta `backend` y ejecute:
    ```bash
    # En Windows (PowerShell/CMD):
    npm install
    ```
3.  **Compilar y Ejecutar Test de Integración**:
    Ejecute el script de verificación criptográfica para validar que todo funcione en el nuevo sistema operativo:
    ```bash
    npm run build
    npx ts-node src/test_flow.ts
    ```
4.  **Iniciar Servidor de Desarrollo**:
    ```bash
    npm run dev
    ```
    El backend escuchará en `http://localhost:3000`.

---

## 4. Próximos Pasos: ¿Dónde y Cómo Comenzar a Trabajar?

Al continuar en la nueva PC, las prioridades de desarrollo recomendadas son las siguientes:

### Paso 1: Conexión del Cliente Frontend con el Backend Real
**Dónde trabajar:** Modificar el archivo [app.js](file:///c:/Users/Joaquin%20Obando/Desktop/id%20global/app.js) del frontend.
*   **Qué hacer**: Reemplazar las funciones de simulación local de `app.js` (como `enrollUser` y `startVerificationScan`) por llamadas HTTP reales utilizando `fetch()` hacia el servidor de backend local (`http://localhost:3000`).
*   **Detalle**: Al hacer clic en "Acuñar Credencial", el frontend enviará un `POST` al `/api/v1/identities/issue` del backend. El JSON devuelto (que contiene la credencial SD-JWT firmada y el par de llaves del Holder) deberá guardarse en el estado de la billetera del cliente para pintar la tarjeta y el código QR real.

### Paso 2: Integración Real con Hyperledger Indy/Aries
**Dónde trabajar:** Modificar el archivo [backend/src/routes/identity.ts](file:///c:/Users/Joaquin%20Obando/Desktop/id%20global/backend/src/routes/identity.ts).
*   **Qué hacer**: Sustituir el mapa `dltLedgerRegistry` (que actúa como base de datos en memoria del ledger) por integraciones reales utilizando las librerías oficiales de Hyperledger.
*   **Librerías a integrar**: `@hyperledger/indy-vdr` y `@hyperledger/aries-askar`.
*   **Detalle**: Al emitir una credencial, el servidor debe escribir el DID Document con la clave pública del Holder directamente en un ledger Indy activo (por ejemplo, en una red Sandbox local utilizando Docker).

### Paso 3: Servidor de Revocación y Árbol de Acumulación (Status List)
**Dónde trabajar:** Crear `backend/src/routes/revocation.ts`.
*   **Qué hacer**: Implementar un registro de revocación que permita anular credenciales de forma criptográfica.
*   **Detalle**: Crear un array de bits (*Status List 2021*) gestionado en el servidor. Cuando un usuario pierda su celular, el portal gubernamental cambiará el estado del bit de la credencial del titular. El verificador consultará este árbol de bits durante la llamada a `/verify` para certificar la vigencia del ID.

### Paso 4: Cifrado Híbrido mTLS para Canales Seguros
**Dónde trabajar:** Configuración de la red y Express HTTPS.
*   **Qué hacer**: Proteger los endpoints API de emisión.
*   **Detalle**: Levantar el servidor Express sobre HTTPS forzando **mTLS (Mutual TLS)**. Investigar y configurar ciphers híbridos PQC (por ejemplo, mediante un túnel inverso con Ngrok o túneles de OpenSSL que soporten combinaciones de Kyber/ML-KEM y X25519) para impedir interceptaciones en tránsito.
