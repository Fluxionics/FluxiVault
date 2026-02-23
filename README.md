# 🔐 FLUXI VAULT PRO - Quantum Security Edition

**Fluxi Vault Pro** es una plataforma de ciberseguridad avanzada diseñada para la protección de activos digitales, identidades sintéticas y archivos sensibles. Este software opera bajo el principio de **Privacidad Absoluta**, asegurando que el acceso sea exclusivo al propietario de la Clave Maestra.

> **ESTADO DEL SOFTWARE:** Código Abierto / Distribución Standalone (.exe).

## 🛡️ Arquitectura de Seguridad Quantum-Ready

El núcleo del sistema utiliza una arquitectura de cifrado en cascada para garantizar que los datos sean indescifrables incluso ante intentos de computación avanzada:

* **Cifrado en Capas (Triple Shield):** Cada dato es procesado secuencialmente por **ChaCha20Poly1305** -> **AES-256 GCM** -> **ChaCha20Poly1305**.
* **Hardware-Binding:** El sistema genera una semilla única basada en el `HWID` (UUID del hardware) del equipo, impidiendo que la base de datos sea exportada y abierta en otro PC.
* **Derivación de Clave:** Implementación de `PBKDF2HMAC` con algoritmo **SHA-512** y un ciclo de **600,000 iteraciones** para neutralizar ataques de fuerza bruta modernos.

## 🚀 Módulos y Capacidades

### 1. Gestión de Identidades (Quantum Identity)
* **Identidades Sintéticas:** Generación instantánea de perfiles con nombres, CURP, RFC, NSS y correos electrónicos funcionales.
* **Protección Financiera:** Simulación de tarjetas de crédito (Visa/Mastercard), CLABE interbancaria y saldos aleatorios para pruebas de seguridad o anonimato.
* **Datos Vehiculares:** Generación de registros de autos y placas vinculadas a la identidad.

### 2. Bóveda Digital (Vault)
* **Categorización Inteligente:** Organización de credenciales por Redes Sociales, Bancos, Trabajo, etc.
* **Medidor de Fuerza:** Análisis en tiempo real de la seguridad de tus contraseñas mediante puntuación de 0 a 100.
* **Generador Aleatorio:** Creación de claves de hasta 64 caracteres con selección de símbolos, números y mayúsculas.

### 3. Black Hole Storage
* **Ocultación Cruda:** Los archivos se extraen de su ubicación original y se almacenan en la "Shadow Storage".
* **Hasheo de Archivos:** El nombre original se reemplaza por un hash SHA-256 de 20 caracteres, haciendo imposible identificar el contenido sin el software.

### 4. Esteganografía de Firma Digital
* Vínculo de mensajes cifrados a la "huella digital" (hash) de archivos de imagen (PNG, JPG, JPEG).
* A diferencia de la esteganografía tradicional, no altera ni un solo bit de la imagen original, evitando detecciones forenses.

## ⚠️ Protocolos de Emergencia (Anti-Forense)

* **Modo Decoy (Señuelo):** Activa una base de datos "fantasma" con información falsa si se introduce la clave de acceso secundaria.
* **Protocolo de Pánico:** Si se introduce la clave de pánico configurada, el programa ejecuta `shutil.rmtree` sobre todo el directorio raíz de datos, eliminando la evidencia en milisegundos.
* **Ghost Mode:** Pestaña de secretos de "Acceso Único" protegida por la clase `QuantumCrypto`.

## 📋 Detalles de Implementación
* **Directorio Base:** `%LOCALAPPDATA%\WinSystemAuthCore`.
* **Base de Datos:** SQLite v3 con integridad referencial.
* **Librerías Core:** `Cryptography.hazmat`, `CustomTkinter`.

---

## ✒️ Créditos y Autoría
Este software es una propiedad intelectual de:
* **Fluxionics - Guillermo**

---
**ADVERTENCIA:** El uso indebido de este software es responsabilidad del usuario. **Fluxionics** no se hace responsable por la pérdida de claves maestras, ya que al ser un sistema de conocimiento cero, no existe forma de recuperar los datos sin la contraseña original.
