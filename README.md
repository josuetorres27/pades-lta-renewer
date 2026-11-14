# PAdES-LTA Renewer 🔏⏱️

> Sistema automatizado y servicio web minimalista para la preservación a largo plazo y renovación de sellos de tiempo en documentos PDF firmados digitalmente (**PAdES-B-LTA** / ETSI EN 319 142).  
> Proyecto de Investigación — **CI-0140 Calidad de Software** (Universidad de Costa Rica).

---

## 📋 Descripción

Este proyecto implementa una solución de código abierto y servicio web para extender la validez jurídica de documentos electrónicos con firma digital certificada, conforme a la **Ley N° 8454** y la **Política de Formatos Oficiales V.4.0** del MICITT de Costa Rica.

El sistema se conecta a la **Autoridad de Estampado de Tiempo del SINPE (TSA-SINPE)** operada por el Banco Central de Costa Rica (BCCR) mediante el protocolo estándar **RFC 3161** sobre HTTP, e incluye:

- **Cliente TSA-SINPE (`tsa_client.py`)**: Generación y parseo de `TimeStampReq` / `TimeStampResp` (ASN.1 DER).
- **Inspector PKI (`pki_inspector.py`)**: Reconstrucción completa de ramas X.509 hasta la CA Raíz (vía certificados embebidos, `/DSS` y `AIA`), consulta de revocación **OCSP** (RFC 6960) y **CRL** (RFC 5280), verificación de integridad `/ByteRange`, políticas de certificación (OID/CPS) y análisis de vigencia de autoridades raíz e intermedias.
- **Inyector Incremental PAdES-B-LTA (`pdf_injector.py`)**: Actualizaciones incrementales PDF ISO 32000-1/2 para insertar evidencias LTV en `/DSS` (**PAdES-B-LT**) y sellos documentales `/DocTimeStamp` (`ETSI.RFC3161`) sin invalidar firmas anteriores (**PAdES-B-LTA**).
- **Interfaz Web Minimalista (`web/`)**: Zona de arrastrar y soltar PDFs con confirmación inmediata, descarga directa e inspección desplegable de toda la jerarquía PKI hasta la raíz.

---

## 🚀 Instalación y Ejecución

### 1. Requisitos Previos

* Python 3.10 o superior.
* Conexión a Internet (para alcanzar el endpoint público `http://tsa.sinpe.fi.cr/tsaHttp/` y repositorios AIA/OCSP/CRL del SINPE/MICITT).

### 2. Instalación de Dependencias

```bash
pip install -r requirements.txt
```

O en modo desarrollo editable:

```bash
pip install -e .
```

### 3. Iniciar la Interfaz Web Minimalista

```bash
python3 run_web.py
```

Abra su navegador en `http://127.0.0.1:5050` (puede cambiar el puerto con la variable `PORT`). Arrastre uno o varios PDFs para renovarlos en memoria a **PAdES-B-LTA**, descargar el resultado y explorar la cadena completa hasta la **CA Raíz Nacional**.

### 4. Uso por Línea de Comandos (CLI)

**Inyectar `/DSS` + `/DocTimeStamp` directamente en un PDF:**

```bash
python3 examples/inject_pades_lta.py "/ruta/al/documento.pdf"
```

El documento renovado se guarda en `output/<nombre>_LTA.pdf` (o en la ruta especificada como segundo argumento).

**Prueba de Concepto (consumo directo de token `.tst` desde TSA-SINPE):**

```bash
python3 examples/poc_tsa_sinpe.py
```

---

## 🧪 Pruebas Automatizadas

Para ejecutar las pruebas unitarias e integración:

```bash
PYTHONPATH=src pytest -v
```

---

## 👥 Autores
* Gabriel Serrano Rojas (C17497)
* Josue Torres Sibaja (C37853)

**Profesor Guía:** Ph.D. Alexander Barquero Elizondo  
**Institución:** Universidad de Costa Rica (UCR)
