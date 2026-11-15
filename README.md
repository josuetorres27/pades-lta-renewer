# PAdES-LTA Renewer

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3%2B-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![PAdES](https://img.shields.io/badge/PAdES-B--LTA-1F6FEB?style=flat-square)](#standards)
[![RFC 3161](https://img.shields.io/badge/RFC-3161-1F6FEB?style=flat-square)](https://www.rfc-editor.org/rfc/rfc3161)
[![Tests](https://img.shields.io/badge/Tests-pytest-0A9EDC?style=flat-square&logo=pytest&logoColor=white)](#testing)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

PAdES-LTA Renewer is a Python library, set of command-line examples and minimal Flask web interface that extends the long-term verifiability of digitally signed PDF documents. It collects the validation material of every signature (X.509 certificates, CRLs and OCSP responses) into the document's `/DSS` dictionary and then appends an RFC 3161 document timestamp (`/DocTimeStamp`) issued by the SINPE Time Stamping Authority (TSA-SINPE) of the Central Bank of Costa Rica (BCCR). Both steps are written as PDF incremental updates, so existing signatures are not modified, and the result is a PAdES-B-LTA document as defined in ETSI EN 319 142-1.

It is a research project for the course CI-0140 Software Quality at the University of Costa Rica (UCR), guided by Professor Alexander Barquero Elizondo, Ph.D. The project targets Costa Rica's digital signature framework: Law 8454 (Ley de Certificados, Firmas Digitales y Documentos Electrónicos) and the MICITT Política de Formatos Oficiales V.4.0. The web interface and the messages printed by the tools are in Spanish.

---

## Features

- **TSA-SINPE Client (`tsa_client.py`):** Builds RFC 3161 `TimeStampReq` structures (SHA-256 by default, random 64-bit nonce, certificate request) in ASN.1 DER, sends them over HTTP POST to `http://tsa.sinpe.fi.cr/tsaHttp/` and parses the `TimeStampResp`: status, nonce match, generation time, policy OID, serial number and attached certificates.
- **Command Line (`cli.py`):** `pades-renewer inspect` and `pades-renewer renew` subcommands, with human-readable or `--json` output, `--no-remote` for purely offline analysis and exit codes suitable for scripting.
- **PKI Inspector (`pki_inspector.py`):** Lists every signature and document timestamp in a PDF, recomputes the `/ByteRange` digest and compares it with the CMS `messageDigest` attribute or the timestamp's message imprint, and builds each X.509 chain toward a self-signed root from embedded certificates, `/DSS` and AIA `caIssuers` downloads, verifying every certificate signature against its issuer. The evidence already carried by the document (`/DSS`) is always used, so a PAdES-B-LT file can be validated without network access, and revocation evidence past its `nextUpdate` is reported as stale instead of passing for current.
- **Tolerant Inspection:** A signature whose `/Contents` is not a CMS container (a legacy `/adbe.x509.rsa_sha1` field, a truncated token, a field written by another signer) is reported as its own entry instead of aborting the analysis of the rest of the document, and a `/DSS` dictionary that is not a dictionary is flagged and rebuilt on renewal.
- **Certificate Analysis:** Reports validity status per chain link (with a 180-day "expiring soon" threshold), role (signer, TSA, issuing CA, policy CA, root CA), key and signature algorithms, key usage, certificate policies (OID, explicit text, CPS URLs) and revocation status via OCSP (RFC 6960) and CRL (RFC 5280).
- **Profile Detection:** Classifies the document as PAdES-B-B, PAdES-B-T, PAdES-B-LT or PAdES-B-LTA from the signatures, timestamps and `/DSS` dictionary it finds.
- **Incremental Injector (`pdf_injector.py`):** Appends a `/DSS` revision (certificates, CRLs and OCSP responses, including the active TSA's chain) with `/Extensions` ADBE ExtensionLevel 8, then appends an invisible `/DocTimeStamp` field (`/SubFilter /ETSI.RFC3161`) whose `/Contents` holds the TSA-SINPE token. It supports both classic cross-reference tables and cross-reference streams and rejects encrypted PDFs.
- **Web Interface (`web/`):** Flask application with a drag-and-drop zone for one or more PDFs (up to 50 MB each), in-memory processing, a download link for the renewed `<name>_LTA.pdf` and an expandable view of every PKI chain up to the root.

---

## Standards

| Standard | Use in the Code |
| :--- | :--- |
| **ETSI EN 319 142-1 (PAdES)** | Signature levels B-B, B-T, B-LT and B-LTA; `/DSS` and `/DocTimeStamp` structures |
| **ISO 32000-1/2 (PDF)** | Incremental updates, `/ByteRange`, `/AcroForm` signature fields, xref tables and streams |
| **[RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html)** | `TimeStampReq` / `TimeStampResp` exchange with TSA-SINPE |
| **[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html)** | X.509 certificate parsing, chain building and CRL checks |
| **[RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html)** | OCSP requests and response parsing |

---

## How It Works

`renew_pdf_to_lta()` renews a PDF held in memory in these steps:

- **Inspect:** Analyzes the original document and downloads missing issuer certificates, CRLs and OCSP responses.
- **Collect TSA Evidence:** Requests a probe timestamp from TSA-SINPE to obtain the active TSA certificate chain and its revocation data (cached in memory for one hour).
- **Append `/DSS`:** Writes the first incremental update with the merged `/DSS` dictionary (PAdES-B-LT).
- **Reserve the Timestamp Field:** Writes the second incremental update with a `/DocTimeStamp` field, a reserved 8,192-byte `/Contents` placeholder and a fixed-width `/ByteRange`.
- **Stamp:** Hashes the covered byte ranges, requests the token from TSA-SINPE and writes it into `/Contents`; if the token does not fit, it rebuilds the revision once with a larger buffer.
- **Verify:** Inspects the renewed document again and returns a `RenewalResult` with the original and new profiles, `/DSS` counts, timestamp data and both inspection reports.

---

## Limitations

- **Signature Checks:** The inspector compares `/ByteRange` digests and verifies certificate-chain signatures, but it does not verify the CMS signature value of signers, the signature of timestamp tokens or the signatures of OCSP responses and CRLs.
- **Trust Anchors:** A chain "reaches the root" when it ends in a self-signed CA certificate; there is no configured trust store.
- **Profile Detection:** The PAdES level is inferred from the presence of signatures, timestamps and `/DSS`; it is not a full ETSI conformance validation. A document whose signatures cannot be interpreted at all is reported as `Desconocido` instead of being classified silently.
- **Revocation Freshness:** Evidence past its `nextUpdate` is labelled `stale: true` in the report, but it is still the evidence used: validity is not re-evaluated at the signing or stamping time.
- **Legacy Containers:** A signature stored as a bare X.509 certificate (`/adbe.x509.rsa_sha1`) yields its signer certificate and chain, but that container does not embed a digest, so its `/ByteRange` cannot be recomputed.
- **Network Access:** Renewal needs access to TSA-SINPE and, unless `fetch_remote=False` or `--no-remote` is used, to the AIA, OCSP and CRL endpoints listed in the certificates.

---

## Project Structure

```text
pades-lta-renewer/
├── examples/
│   ├── inject_pades_lta.py      # Script: renew a PDF to PAdES-B-LTA
│   └── poc_tsa_sinpe.py         # Proof of concept: request a token from TSA-SINPE
├── src/
│   └── pades_renewer/
│       ├── __init__.py
│       ├── cli.py               # `pades-renewer` console entry point
│       ├── pdf_injector.py      # Incremental /DSS and /DocTimeStamp injection
│       ├── pki_inspector.py     # Signature, X.509 chain and revocation inspection
│       ├── tsa_client.py        # RFC 3161 client for TSA-SINPE
│       ├── utils.py             # Hash helpers
│       └── web/
│           ├── __init__.py
│           ├── app.py           # Flask application factory and API
│           ├── static/
│           │   ├── app.js
│           │   └── styles.css
│           └── templates/
│               └── index.html
├── tests/
│   ├── support_pki.py           # Synthetic PKI, CRL/OCSP and signed-PDF fixtures
│   ├── test_cli.py
│   ├── test_pki_and_injector.py
│   ├── test_revocation_evidence.py
│   ├── test_robust_inspection.py
│   └── test_tsa_client.py
├── .gitignore
├── LICENSE
├── README.md
├── conftest.py                  # Lets `pytest` run from a checkout, without installing
├── pyproject.toml               # Packaging, console script and pytest/ruff config
├── requirements.txt
└── run_web.py                   # Web interface launcher
```

---

## Getting Started

### Prerequisites

- Python 3.10 or later.
- Internet access to reach `http://tsa.sinpe.fi.cr/tsaHttp/` and the AIA, OCSP and CRL repositories referenced by the certificates.

### Installation

```bash
git clone https://github.com/josuetorres27/pades-lta-renewer.git
cd pades-lta-renewer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The dependencies are `asn1crypto`, `requests`, `cryptography`, `pypdf` and `Flask`. To install the package (and the `pades-renewer` command) in editable mode instead, with the test tooling:

```bash
pip install -e ".[dev]"
```

`pyproject.toml` declares the package, its dependencies, the console script and the `pytest`/`ruff` configuration; `templates/` and `static/` are shipped as package data so an installed copy can serve the web interface.

### Run

```bash
python3 run_web.py
```

Open `http://127.0.0.1:5050` in a browser. The `HOST` and `PORT` environment variables change the bind address and port:

```bash
HOST=0.0.0.0 PORT=8080 python3 run_web.py
```

---

## Usage

### Web Interface

Drop one or more signed PDFs on the page. Each file is renewed in memory to PAdES-B-LTA, and its result card shows the original and new profiles, the timestamp data, a download link and the PKI chains. The server keeps the 32 most recent renewed files in memory for download.

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| **`/`** | GET | Web interface |
| **`/api/renew`** | POST | Renews the PDF sent in the `file` form field and returns a JSON report |
| **`/api/download/<file_id>`** | GET | Downloads a renewed PDF |

### Command Line

The installed package exposes `pades-renewer`. Inspect a document (add `--json` for the full report, `--no-remote` to use only the evidence carried by the PDF):

```bash
pades-renewer inspect "/path/to/document.pdf"
pades-renewer inspect "/path/to/document.pdf" --no-remote --json
```

Renew it, writing `<name>_LTA.pdf` next to the original or the path given with `-o`:

```bash
pades-renewer renew "/path/to/document.pdf"
pades-renewer renew "/path/to/document.pdf" -o "/path/to/renewed.pdf"
pades-renewer renew "/path/to/document.pdf" --algorithm sha512 --token-buffer 16384
```

`pades-renewer` exits with `0` on success, `1` when the renewal fails (the reason goes to stderr) and `2` on usage errors, so it can drive a script or a pipeline. Without installing the package the same commands run as `python3 -m pades_renewer.cli`.

The example scripts remain available and do the same through the Python API:

```bash
python3 examples/inject_pades_lta.py "/path/to/document.pdf"
python3 examples/inject_pades_lta.py "/path/to/document.pdf" "/path/to/renewed.pdf"
```

Request a timestamp token from TSA-SINPE for a sample text, or for a file given as an argument, and save it to `output/sample_sinpe_timestamp.tst`:

```bash
python3 examples/poc_tsa_sinpe.py
python3 examples/poc_tsa_sinpe.py "/path/to/file.pdf"
openssl ts -reply -in output/sample_sinpe_timestamp.tst -text
```

### Python API

```python
from pades_renewer import inspect_pdf_public, renew_pdf_to_lta

with open("document.pdf", "rb") as f:
    pdf_bytes = f.read()

report = inspect_pdf_public(pdf_bytes)
print(report["pades_profile"])

result = renew_pdf_to_lta(pdf_bytes)
if result.success:
    with open("document_LTA.pdf", "wb") as f:
        f.write(result.output_pdf_bytes)
```

Both functions accept `fetch_remote=False` to stay offline: only the certificates, CRL and OCSP responses already inside the document are used. `renew_pdf_to_lta` reports every failure in `RenewalResult.error_message` instead of raising, and only rejects invalid arguments (`algorithm`, `token_buffer_bytes`) with `ValueError`.

The inspection report also carries the fields that describe what could not be verified: `unreadable_signatures` (plus a `warnings` list), `dss.malformed`/`dss.error` for a broken `/DSS` dictionary, `signature.signer_certificate_found`, and `revocation.stale` for evidence past its `nextUpdate`.

---

## Testing

`pytest` is part of the `dev` extra (`pip install -e ".[dev]"`); a root `conftest.py` adds `src/` to `sys.path`, so the suite also runs from a plain checkout:

```bash
pytest -v
```

| Test File | Tests | Scope |
| :--- | :---: | :--- |
| **`tests/test_tsa_client.py`** | 3 | Hashing, `TimeStampReq` structure and a live request to TSA-SINPE |
| **`tests/test_pki_and_injector.py`** | 6 | Offline renewal with a synthetic PKI and mocked TSA (classic xref, xref stream, oversized token), Flask routes and validation, end-to-end web renewal and an optional live renewal of a real PDF |
| **`tests/test_revocation_evidence.py`** | 10 | `/DSS` evidence reused with and without network, `stale` evidence, fresh-over-stale selection, OCSP `CertID` hashes checked against an independent RFC 6960 computation, revocation propagated to the chain node and preserved across renewal |
| **`tests/test_robust_inspection.py`** | 22 | Legacy `/adbe.x509.rsa_sha1` containers, unreadable signatures, empty `SignerInfo`, corrupt and single-reference `/DSS`, signer-certificate resolution, renewal of damaged documents, argument validation and non-raising error reporting |
| **`tests/test_cli.py`** | 14 | `inspect`/`renew` output, `--json`, `-o`, hash algorithm, exit codes, `--version` and execution through `python -m pades_renewer.cli` |
| **`Total`** | **55** | |

Every test except the two live ones runs offline against `tests/support_pki.py`, which builds a synthetic PKI, real CRL and OCSP structures, signed PDFs and a local TSA. `test_live_tsa_sinpe_request` needs network access to TSA-SINPE. `test_real_costa_rica_pdf_live_renewal` is skipped unless the `PADES_REAL_PDF` environment variable points to a signed PAdES-B-T PDF:

```bash
PADES_REAL_PDF="/path/to/signed.pdf" pytest -v
```

---

## License

This project is licensed under the [MIT License](LICENSE).

---

Created by **Gabriel Serrano Rojas** ([LinkedIn](https://www.linkedin.com/in/gabrielserranor/) · [GitHub](https://github.com/GabrielSerranoUCR)) and **Josue Torres Sibaja** ([Portfolio](https://josuetorressibaja.com/) · [LinkedIn](https://www.linkedin.com/in/josue-torres-sibaja/) · [Email](mailto:dev.josue.torres@gmail.com))
