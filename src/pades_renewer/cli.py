"""
Interfaz de línea de comandos de PAdES-LTA Renewer.

Permite inspeccionar un PDF firmado y renovarlo a PAdES-B-LTA sin escribir Python:

    pades-renewer inspect contrato.pdf
    pades-renewer renew contrato.pdf -o contrato_LTA.pdf

Los mensajes están en español, igual que el resto de las herramientas del proyecto.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .pdf_injector import RenewalResult, renew_pdf_to_lta
from .pki_inspector import inspect_pdf_public
from .tsa_client import TSASinpeClient

PROGRAMA = "pades-renewer"
ALGORITMOS = ("sha256", "sha384", "sha512")
DEFAULT_TSA_URL = TSASinpeClient.DEFAULT_HTTP_URL
DEFAULT_TSA_TIMEOUT = TSASinpeClient.DEFAULT_TIMEOUT_SECONDS


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAMA,
        description="Inspección y renovación de sellos de tiempo PAdES-B-LTA (RFC 3161 / ETSI EN 319 142).",
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAMA} {__version__}")
    subparsers = parser.add_subparsers(dest="comando", required=True, metavar="{inspect,renew}")

    insp = subparsers.add_parser(
        "inspect",
        help="Analiza firmas, cadenas PKI, revocación y perfil PAdES del documento.",
        description="Analiza firmas, cadenas PKI, revocación y perfil PAdES del documento.",
    )
    insp.add_argument("archivo", help="Ruta del PDF a inspeccionar.")
    insp.add_argument("--json", action="store_true", help="Emite el informe completo en JSON.")
    insp.add_argument(
        "--no-remote",
        action="store_true",
        help="No descarga certificados, CRL ni OCSP: usa solo la evidencia embebida en el PDF.",
    )
    insp.add_argument("--timeout", type=int, default=8, help="Segundos de espera por descarga remota (por defecto 8).")

    ren = subparsers.add_parser(
        "renew",
        help="Añade /DSS y un /DocTimeStamp de la TSA-SINPE para obtener PAdES-B-LTA.",
        description="Añade /DSS y un /DocTimeStamp de la TSA-SINPE para obtener PAdES-B-LTA.",
    )
    ren.add_argument("archivo", help="Ruta del PDF firmado a renovar.")
    ren.add_argument(
        "-o",
        "--salida",
        help="Ruta del PDF renovado (por defecto <nombre>_LTA.pdf junto al original).",
    )
    ren.add_argument(
        "--algorithm",
        default="sha256",
        choices=ALGORITMOS,
        help="Algoritmo de digest del sello (por defecto sha256).",
    )
    ren.add_argument(
        "--token-buffer",
        type=int,
        default=8192,
        help="Bytes reservados en /Contents para el token RFC 3161 (por defecto 8192).",
    )
    ren.add_argument(
        "--tsa-url",
        default=DEFAULT_TSA_URL,
        help="URL del servicio RFC 3161 (por defecto TSA-SINPE).",
    )
    ren.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TSA_TIMEOUT,
        help="Segundos de espera de la TSA (por defecto 15).",
    )
    ren.add_argument(
        "--no-remote",
        action="store_true",
        help="No descarga evidencias adicionales: usa solo lo embebido en el PDF.",
    )
    ren.add_argument("--json", action="store_true", help="Emite el resultado en JSON.")
    return parser


def _read_pdf(path: Path) -> bytes:
    if not path.is_file():
        raise SystemExit(f"Error: no se encontró el archivo '{path}'.")
    data = path.read_bytes()
    if not data.lstrip().startswith(b"%PDF-"):
        raise SystemExit(f"Error: '{path}' no tiene cabecera PDF válida (%PDF-).")
    return data


def _default_output_path(path: Path) -> Path:
    stem = path.stem
    return path.with_name(f"{stem}_LTA.pdf")


def _format_bytes(total: int) -> str:
    return f"{total:,} bytes".replace(",", " ")


def _describe_branch_report(sig: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    for branch in sig.get("branches", []):
        nodes = branch.get("nodes", [])
        if not nodes:
            continue
        chain = " → ".join(str(n.get("common_name") or "?") for n in nodes)
        estado = "válida" if branch.get("chain_cryptographically_valid") else "incompleta"
        destino = (
            f"raíz «{branch.get('root_common_name')}»"
            if branch.get("reaches_root")
            else "sin alcanzar una CA raíz autoconsignada"
        )
        lines.append(f"      cadena: {chain}")
        lines.append(f"      estado: {estado}, {destino}")
        leaf = nodes[0]
        rev = leaf.get("revocation") or {}
        rev_status = rev.get("status") or "not_checked"
        metodo = rev.get("method") or "sin evidencia"
        detalle = f"      revocación: {rev_status} ({metodo}"
        if rev.get("source_url"):
            detalle += f", {rev['source_url']}"
        if rev.get("stale"):
            detalle += ", evidencia expirada"
        detalle += ")"
        lines.append(detalle)
    return lines


def _report_lines(document: Path, report: Dict[str, Any]) -> List[str]:
    lines = [
        f"Documento: {document.name} ({_format_bytes(report['file_size_bytes'])}, "
        f"{report['pages_count']} páginas)",
        f"Perfil PAdES: {report['pades_profile']}",
        f"Firmas detectadas: {report['signatures_count']}"
        + (f" ({report['unreadable_signatures']} ilegibles)" if report.get("unreadable_signatures") else ""),
    ]

    dss = report.get("dss") or {}
    if dss.get("present") and not dss.get("malformed"):
        lines.append(
            f"/DSS: presente ({dss.get('certs_count', 0)} certificados, "
            f"{dss.get('crls_count', 0)} CRL, {dss.get('ocsps_count', 0)} OCSP)"
        )
    elif dss.get("malformed"):
        lines.append(f"/DSS: presente pero mal formado ({dss.get('error')})")
    else:
        lines.append("/DSS: no presente")

    if report.get("effective_protection_until"):
        lines.append(f"Protección temporal vigente hasta: {report['effective_protection_until'][:19]} UTC")

    for sig in report.get("signatures", []):
        kind = sig.get("kind")
        if kind == "doc_timestamp":
            sello = sig.get("timestamp") or {}
            lines.append(f"  - {sig['field_name']} [sello documental] emitido {sello.get('gen_time_utc')}")
        elif kind == "unreadable":
            lines.append(f"  - {sig['field_name']} [ilegible] {sig.get('error')}")
        else:
            estado = {True: "correcto", False: "no coincide", None: "no verificable"}[
                sig.get("byterange_hash_valid")
            ]
            lines.append(
                f"  - {sig['field_name']} [firma] SubFilter={sig.get('subfilter') or '?'} "
                f"digest={sig.get('digest_algorithm') or '?'} ByteRange={estado}"
            )
            if sig.get("signer_certificate_found") is False:
                lines.append("      certificado del firmante: no identificable en el contenedor")
            lines.extend(_describe_branch_report(sig))

    for warning in report.get("warnings", []):
        lines.append(f"Advertencia: {warning}")
    return lines


def _renewal_payload(result: RenewalResult, output_path: Optional[Path]) -> Dict[str, Any]:
    return {
        "success": result.success,
        "original_profile": result.original_profile,
        "new_profile": result.new_profile,
        "field_name": result.field_name,
        "hash_algorithm": result.hash_algorithm,
        "tsa_timestamp_utc": result.tsa_timestamp_utc,
        "tsa_policy_oid": result.tsa_policy_oid,
        "tsa_serial_number": result.tsa_serial_number,
        "dss_updated": result.dss_updated,
        "dss_counts": result.dss_counts,
        "effective_protection_until": result.effective_protection_until,
        "output_path": str(output_path) if output_path else None,
        "output_size_bytes": len(result.output_pdf_bytes) if result.output_pdf_bytes else 0,
        "error_message": result.error_message,
        "pre_inspection": result.pre_inspection,
        "post_inspection": result.post_inspection,
    }


def _cmd_inspect(args: argparse.Namespace) -> int:
    document = Path(args.archivo)
    pdf_bytes = _read_pdf(document)
    report = inspect_pdf_public(pdf_bytes, fetch_remote=not args.no_remote)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    else:
        print("\n".join(_report_lines(document, report)))
    return 0


def _cmd_renew(args: argparse.Namespace) -> int:
    document = Path(args.archivo)
    pdf_bytes = _read_pdf(document)
    output_path = Path(args.salida) if args.salida else _default_output_path(document)

    client = TSASinpeClient(tsa_url=args.tsa_url, timeout=args.timeout)
    result = renew_pdf_to_lta(
        pdf_bytes,
        tsa_client=client,
        algorithm=args.algorithm,
        token_buffer_bytes=args.token_buffer,
        fetch_remote=not args.no_remote,
    )

    if not result.success or not result.output_pdf_bytes:
        if args.json:
            print(json.dumps(_renewal_payload(result, None), ensure_ascii=False, indent=2, default=str))
        else:
            print(f"Error durante la renovación: {result.error_message}", file=sys.stderr)
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(result.output_pdf_bytes)

    if args.json:
        print(json.dumps(_renewal_payload(result, output_path), ensure_ascii=False, indent=2, default=str))
    else:
        print(f"Perfil: {result.original_profile} → {result.new_profile}")
        print(f"Campo inyectado: {result.field_name} (/ETSI.RFC3161)")
        print(
            f"Evidencias /DSS: {result.dss_counts['certs']} certificados, "
            f"{result.dss_counts['crls']} CRL, {result.dss_counts['ocsps']} OCSP"
        )
        print(f"Sello emitido (UTC): {result.tsa_timestamp_utc} | Serial TST: {result.tsa_serial_number}")
        if result.effective_protection_until:
            print(f"Protección temporal hasta: {result.effective_protection_until[:19]} UTC")
        print(f"Archivo guardado en: {output_path} ({_format_bytes(len(result.output_pdf_bytes))})")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Punto de entrada de la consola ``pades-renewer``."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.comando == "inspect":
        return _cmd_inspect(args)
    if args.comando == "renew":
        return _cmd_renew(args)
    parser.error(f"comando desconocido: {args.comando}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
