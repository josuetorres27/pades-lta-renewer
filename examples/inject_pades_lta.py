#!/usr/bin/env python3
"""
Script CLI: Inyección incremental PAdES-B-LT (/DSS) + PAdES-B-LTA (/DocTimeStamp)
Autor: Proyecto PAdES-LTA Renewer (UCR - CI-0140 Calidad de Software)
"""

import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / "src"))

from pades_renewer import renew_pdf_to_lta


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 examples/inject_pades_lta.py <ruta_documento.pdf> [ruta_salida_LTA.pdf]")
        sys.exit(1)

    src_path = Path(sys.argv[1])
    if not src_path.is_file():
        print(f"Error: No se encuentra el archivo '{src_path}'.")
        sys.exit(1)

    if len(sys.argv) >= 3:
        out_path = Path(sys.argv[2])
    else:
        output_dir = project_root / "output"
        output_dir.mkdir(exist_ok=True)
        out_path = output_dir / f"{src_path.stem}_LTA.pdf"

    with open(src_path, "rb") as f:
        pdf_bytes = f.read()

    print(f"Procesando '{src_path.name}' ({len(pdf_bytes):,} bytes)...")
    res = renew_pdf_to_lta(pdf_bytes)

    if not res.success or not res.output_pdf_bytes:
        print(f"Error durante la renovacion: {res.error_message}")
        sys.exit(1)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(res.output_pdf_bytes)

    print(f"Perfil: {res.original_profile} -> {res.new_profile}")
    print(f"Campo inyectado: {res.field_name} (ETSI.RFC3161)")
    print(f"Evidencias /DSS: {res.dss_counts['certs']} certs, {res.dss_counts['crls']} CRLs, {res.dss_counts['ocsps']} OCSPs")
    print(f"Sello emitido (UTC): {res.tsa_timestamp_utc} | Serial TST: {res.tsa_serial_number}")
    print(f"Proteccion vigente hasta: {(res.effective_protection_until or '')[:10]}")
    print(f"Archivo guardado en: {out_path} ({len(res.output_pdf_bytes):,} bytes)")


if __name__ == "__main__":
    main()
