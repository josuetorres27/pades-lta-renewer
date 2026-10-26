# PAdES-LTA Renewer 🔏⏱️

> Sistema automatizado y servicio web para la preservación a largo plazo y renovación de sellos de tiempo en documentos PDF firmados digitalmente (**PAdES-B-LTA** / ETSI EN 319 142).  
> Proyecto de Investigación --- **CI-0140 Calidad de Software** (Universidad de Costa Rica).

---

## 📋 Descripción

Este proyecto implementa una solución de código abierto y servicio web para extender la validez jurídica de documentos electrónicos con firma digital certificada, conforme a la **Ley N° 8454** y la **Política de Formatos Oficiales V.4.0** del MICITT de Costa Rica.

El sistema se conecta a la **Autoridad de Estampado de Tiempo del SINPE (TSA-SINPE)** operada por el Banco Central de Costa Rica (BCCR) mediante el protocolo estándar **RFC 3161** sobre HTTP, permitiendo inyectar sellos documentales de archivo y evidencias LTV de forma incremental.

---

## 🚀 Prueba de Concepto (POC) - Consumo de la TSA-SINPE

El repositorio incluye un cliente Python modular y un script interactivo para demostrar el consumo del servicio de sellado oficial del BCCR.

### 1. Requisitos Previos

* Python 3.10 o superior.
* Conexión a Internet (para alcanzar el endpoint público `http://tsa.sinpe.fi.cr/tsaHttp/`).

### 2. Instalación de Dependencias

```bash
pip install -r requirements.txt
```

O instalando en modo desarrollo editable:

```bash
pip install -e .
```

### 3. Ejecutar la Prueba de Concepto

Para sellar un buffer de prueba en memoria:

```bash
python3 examples/poc_tsa_sinpe.py
```

Para sellar un archivo específico (por ejemplo un PDF):

```bash
python3 examples/poc_tsa_sinpe.py ruta/a/tu_documento.pdf
```

### 4. Inspección del Token Recibido con OpenSSL

El script guarda el token ASN.1 DER generado en `output/sample_sinpe_timestamp.tst`. Puedes examinar sus atributos criptográficos con:

```bash
openssl ts -reply -in output/sample_sinpe_timestamp.tst -text
```

Verás:
* La fecha y hora oficial UTC de Costa Rica.
* El OID de la Política Nacional: `2.16.188.1.1.1.1.5`.
* El número de serie único emitido por la TSA-SINPE.
* El certificado firmante de la jerarquía nacional de certificadores.

---

## 🧪 Pruebas Automatizadas

Para ejecutar las pruebas unitarias y de integración:

```bash
pytest -v
```

---

## 👥 Autores
* Gabriel Serrano Rojas (C17497)
* Josué Torres Sibaja (C37853)

**Profesor Guía:** Ph.D. Alexander Barquero Elizondo  
**Institución:** Universidad de Costa Rica (UCR)
