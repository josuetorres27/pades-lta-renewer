"""
Cliente para la Autoridad de Estampado de Tiempo del SINPE (TSA-SINPE - BCCR)
Implementación conforme a RFC 3161 y a la Política de Formatos Oficiales del MICITT.
"""

from dataclasses import dataclass
from datetime import datetime
import os
from typing import Optional, Union, Dict, Any
import requests
from asn1crypto import tsp, algos, cms

from .utils import compute_hash


@dataclass
class TimestampResult:
    """
    Estructura de datos que encapsula el resultado de una solicitud de sellado de tiempo.
    """
    status: str
    is_granted: bool
    generated_time: Optional[datetime]
    policy_oid: Optional[str]
    serial_number: Optional[int]
    hash_algorithm: Optional[str]
    hashed_message_hex: Optional[str]
    nonce: Optional[int]
    tsa_certificates_count: int
    raw_token_der: Optional[bytes]
    raw_response_der: bytes
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convierte los metadatos principales a un diccionario legible."""
        return {
            "status": self.status,
            "is_granted": self.is_granted,
            "generated_time_utc": self.generated_time.isoformat() if self.generated_time else None,
            "policy_oid": self.policy_oid,
            "serial_number": str(self.serial_number) if self.serial_number is not None else None,
            "hash_algorithm": self.hash_algorithm,
            "hashed_message": self.hashed_message_hex,
            "nonce": self.nonce,
            "tsa_certificates_count": self.tsa_certificates_count,
            "token_size_bytes": len(self.raw_token_der) if self.raw_token_der else 0,
            "error_message": self.error_message
        }


class TSASinpeClient:
    """
    Cliente para interactuar con el servicio de Sellado de Tiempo (RFC 3161)
    de la Autoridad de Estampado de Tiempo del SINPE (Banco Central de Costa Rica).
    """

    DEFAULT_HTTP_URL = "http://tsa.sinpe.fi.cr/tsaHttp/"
    DEFAULT_TIMEOUT_SECONDS = 15

    def __init__(self, tsa_url: str = DEFAULT_HTTP_URL, timeout: int = DEFAULT_TIMEOUT_SECONDS):
        self.tsa_url = tsa_url
        self.timeout = timeout

    def build_request(
        self,
        digest: bytes,
        algorithm: str = "sha256",
        nonce: Optional[int] = None,
        cert_req: bool = True
    ) -> tsp.TimeStampReq:
        """
        Construye la estructura ASN.1 TimeStampReq según la sección 2.4.1 del RFC 3161.

        Args:
            digest: Resumen criptográfico del documento o token anterior.
            algorithm: Algoritmo utilizado (por defecto 'sha256').
            nonce: Número aleatorio para validación de frescura (si es None, se genera uno de 64 bits).
            cert_req: Solicitar a la TSA incluir su certificado en el token (True por defecto).

        Returns:
            Objeto TimeStampReq de asn1crypto listo para serializar.
        """
        if nonce is None:
            nonce = int.from_bytes(os.urandom(8), "big")

        req_dict = {
            "version": 1,
            "message_imprint": tsp.MessageImprint({
                "hash_algorithm": algos.DigestAlgorithm({"algorithm": algorithm}),
                "hashed_message": digest
            }),
            "nonce": nonce,
            "cert_req": cert_req
        }
        return tsp.TimeStampReq(req_dict)

    def request_timestamp(
        self,
        digest: bytes,
        algorithm: str = "sha256",
        nonce: Optional[int] = None,
        cert_req: bool = True
    ) -> TimestampResult:
        """
        Envía una solicitud de estampa de tiempo para un digest dado a la TSA-SINPE.

        Args:
            digest: Resumen criptográfico (por ejemplo, SHA-256 de 32 bytes).
            algorithm: Nombre del algoritmo (por defecto 'sha256').
            nonce: Opcional, entero para verificación de respuesta.
            cert_req: Si se solicita que la TSA adjunte su cadena de certificados.

        Returns:
            TimestampResult con los metadatos y el token DER recibido.
        """
        req_obj = self.build_request(digest=digest, algorithm=algorithm, nonce=nonce, cert_req=cert_req)
        req_der = req_obj.dump()
        expected_nonce = req_obj["nonce"].native

        headers = {
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply"
        }

        try:
            response = requests.post(
                self.tsa_url,
                data=req_der,
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
        except requests.RequestException as e:
            return TimestampResult(
                status="network_error",
                is_granted=False,
                generated_time=None,
                policy_oid=None,
                serial_number=None,
                hash_algorithm=algorithm,
                hashed_message_hex=digest.hex(),
                nonce=expected_nonce,
                tsa_certificates_count=0,
                raw_token_der=None,
                raw_response_der=b"",
                error_message=f"Error comunicando con la TSA ({self.tsa_url}): {str(e)}"
            )

        return self.parse_response(response.content, expected_nonce=expected_nonce)

    def stamp_bytes(self, data: Union[bytes, bytearray], algorithm: str = "sha256") -> TimestampResult:
        """
        Calcula el hash de los datos proporcionados y solicita su sellado de tiempo.
        """
        digest = compute_hash(data, algorithm=algorithm)
        return self.request_timestamp(digest=digest, algorithm=algorithm)

    def parse_response(self, response_der: bytes, expected_nonce: Optional[int] = None) -> TimestampResult:
        """
        Interpreta la respuesta ASN.1 TimeStampResp del servidor (RFC 3161 Sección 2.4.2).
        """
        try:
            tsp_resp = tsp.TimeStampResp.load(response_der)
        except Exception as e:
            return TimestampResult(
                status="asn1_parse_error",
                is_granted=False,
                generated_time=None,
                policy_oid=None,
                serial_number=None,
                hash_algorithm=None,
                hashed_message_hex=None,
                nonce=expected_nonce,
                tsa_certificates_count=0,
                raw_token_der=None,
                raw_response_der=response_der,
                error_message=f"Error parseando estructura TimeStampResp ASN.1: {str(e)}"
            )

        status_str = tsp_resp["status"]["status"].native
        is_granted = status_str in ("granted", "granted_with_mods")

        if not is_granted:
            status_string = tsp_resp["status"]["status_string"].native if tsp_resp["status"]["status_string"] else "Desconocido"
            return TimestampResult(
                status=status_str,
                is_granted=False,
                generated_time=None,
                policy_oid=None,
                serial_number=None,
                hash_algorithm=None,
                hashed_message_hex=None,
                nonce=expected_nonce,
                tsa_certificates_count=0,
                raw_token_der=None,
                raw_response_der=response_der,
                error_message=f"Solicitud rechazada por la TSA. Estado: {status_str}, Detalle: {status_string}"
            )

        token = tsp_resp["time_stamp_token"]
        raw_token_der = token.dump()

        signed_data = token["content"]
        encap_content = signed_data["encap_content_info"]
        tst_info_der = encap_content["content"].parsed.dump()
        tst_info = tsp.TSTInfo.load(tst_info_der)

        resp_nonce = tst_info["nonce"].native if tst_info["nonce"] else None
        if expected_nonce is not None and resp_nonce is not None and resp_nonce != expected_nonce:
            return TimestampResult(
                status="nonce_mismatch",
                is_granted=False,
                generated_time=tst_info["gen_time"].native,
                policy_oid=tst_info["policy"].native,
                serial_number=tst_info["serial_number"].native,
                hash_algorithm=tst_info["message_imprint"]["hash_algorithm"]["algorithm"].native,
                hashed_message_hex=tst_info["message_imprint"]["hashed_message"].native.hex(),
                nonce=resp_nonce,
                tsa_certificates_count=0,
                raw_token_der=raw_token_der,
                raw_response_der=response_der,
                error_message=f"Discrepancia en Nonce. Esperado: {expected_nonce}, Recibido: {resp_nonce}"
            )

        certs_count = len(signed_data["certificates"]) if signed_data["certificates"] else 0

        return TimestampResult(
            status=status_str,
            is_granted=True,
            generated_time=tst_info["gen_time"].native,
            policy_oid=tst_info["policy"].native,
            serial_number=tst_info["serial_number"].native,
            hash_algorithm=tst_info["message_imprint"]["hash_algorithm"]["algorithm"].native,
            hashed_message_hex=tst_info["message_imprint"]["hashed_message"].native.hex(),
            nonce=resp_nonce,
            tsa_certificates_count=certs_count,
            raw_token_der=raw_token_der,
            raw_response_der=response_der,
            error_message=None
        )
