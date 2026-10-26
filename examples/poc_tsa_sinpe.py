#!/usr/bin/env python3
"""
Prueba de Concepto (POC): Consumo del servicio de Sellado de Tiempo TSA-SINPE (BCCR)
Autor: Proyecto PAdES-LTA Renewer
UCR - CI-0140 Calidad de Software
"""

import sys
import os
from pathlib import Path
from datetime import timezone, timedelta

# Asegurar que se encuentre el módulo pades_renewer
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / "src"))

from pades_renewer import TSASinpeClient
from pades_renewer.utils import compute_hash


def print_banner():
    banner = """
================================================================================
       PAdES-LTA Renewer - POC Consumo TSA-SINPE (Banco Central de Costa Rica)
                  Protocolo RFC 3161 (Time Stamp Protocol)
================================================================================
    """
    print(banner)


def main():
    print_banner()

    # 1. Definir datos de prueba o recibir un archivo por parámetro
    if len(sys.argv) > 1:
        target_path = Path(sys.argv[1])
        if not target_path.is_file():
            print(f"❌ Error: El archivo '{target_path}' no existe.")
            sys.exit(1)
        print(f"📄 Leyendo archivo objetivo: {target_path}")
        with open(target_path, "rb") as f:
            sample_data = f.read()
        label = target_path.name
    else:
        sample_data = b"Documento de prueba academico - CI-0140 Calidad de Software (UCR) - Preservacion PAdES-LTA"
        label = "Buffer de texto de prueba"

    # 2. Calcular el digest SHA-256
    print(f"\n[1] Calculando resumen criptografico (SHA-256) para: '{label}'...")
    digest = compute_hash(sample_data, "sha256")
    print(f"    Hash calculado (hex): {digest.hex()}")
    print(f"    Longitud del hash: {len(digest)} bytes (256 bits)")

    # 3. Inicializar el cliente TSA
    tsa_url = "http://tsa.sinpe.fi.cr/tsaHttp/"
    print(f"\n[2] Inicializando cliente TSA para endpoint oficial:")
    print(f"    URL: {tsa_url}")
    print(f"    Protocolo: RFC 3161 sobre HTTP POST")
    print(f"    Content-Type: application/timestamp-query")

    client = TSASinpeClient(tsa_url=tsa_url, timeout=15)

    # 4. Enviar solicitud de sellado
    print(f"\n[3] Enviando TimeStampReq al BCCR...")
    result = client.request_timestamp(digest=digest, algorithm="sha256", cert_req=True)

    # 5. Evaluar y mostrar el resultado
    print("\n" + "=" * 80)
    print("                     RESULTADO DE LA RESPUESTA TSA")
    print("=" * 80)

    if not result.is_granted:
        print(f"❌ La solicitud NO fue concedida.")
        print(f"   Estado: {result.status}")
        print(f"   Mensaje de error: {result.error_message}")
        sys.exit(1)

    print("✅ ESTAMPA DE TIEMPO EMITIDA SATISFACTORIAMENTE (Status: GRANTED)\n")
    print(f"   • Politica TSA (OID):       {result.policy_oid}")
    print(f"   • Numero de Serie del TST:  {result.serial_number}")

    if result.generated_time:
        # Hora UTC y hora local de Costa Rica (UTC-6)
        cr_tz = timezone(timedelta(hours=-6))
        local_time = result.generated_time.astimezone(cr_tz)
        print(f"   • Fecha y Hora Oficial UTC: {result.generated_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        print(f"   • Fecha y Hora Costa Rica:  {local_time.strftime('%Y-%m-%d %I:%M:%S %p (UTC-6)')}")

    print(f"   • Algoritmo de Resumen:     {result.hash_algorithm}")
    print(f"   • Hash en el Sello:         {result.hashed_message_hex}")
    print(f"   • Nonce de Verificacion:    {result.nonce}")
    print(f"   • Certificados Adjuntos:    {result.tsa_certificates_count} certificado(s)")
    print(f"   • Tamano del Token (DER):   {len(result.raw_token_der)} bytes")

    # 6. Guardar el token .tst para análisis o inspección con OpenSSL
    output_dir = project_root / "output"
    output_dir.mkdir(exist_ok=True)
    tst_file = output_dir / "sample_sinpe_timestamp.tst"

    with open(tst_file, "wb") as f:
        f.write(result.raw_token_der)

    print("\n" + "-" * 80)
    print(f"💾 Token guardado para inspeccion o inyeccion en PDF:")
    print(f"   Ruta: {tst_file}")
    print(f"   Para inspeccionar con OpenSSL ejecute en su terminal:")
    print(f"   $ openssl ts -reply -in output/sample_sinpe_timestamp.tst -text")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
