"""
Utilidades compartidas por las pruebas: PKI sintética, CRL/OCSP en DER, PDFs firmados
en memoria y una TSA simulada.

Todo se genera localmente: ninguna prueba de este módulo necesita red.
"""

from __future__ import annotations

import hashlib
import io
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, Optional, Sequence

import pypdf
from asn1crypto import cms, ocsp, tsp, x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    NumberObject,
    TextStringObject,
)

from pades_renewer.pdf_injector import (
    BR_PLACEHOLDER,
    _append_incremental_revision,
    _get_max_object_id,
)
from pades_renewer.tsa_client import TimestampResult

#: Puerto cerrado: cualquier descarga remota falla de inmediato, sin salir a la red.
DEAD_HTTP_URL = "http://127.0.0.1:1/recurso"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def build_pki(reference_time: Optional[datetime] = None) -> Dict[str, Any]:
    """
    PKI sintética: CA raíz, TSA y firmante.

    El firmante declara un punto de distribución de CRL en ``DEAD_HTTP_URL`` y un
    respondedor OCSP inalcanzable, de modo que la única evidencia disponible en las
    pruebas es la que se embeba en el documento.
    """
    now = reference_time or _now()
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    root_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI DE PRUEBA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "CA RAIZ PRUEBA CR"),
        ]
    )
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1001)
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    tsa_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI DE PRUEBA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "TSA PRUEBA"),
        ]
    )
    tsa_cert = (
        x509.CertificateBuilder()
        .subject_name(tsa_name)
        .issuer_name(root_name)
        .public_key(tsa_key.public_key())
        .serial_number(2002)
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(tsa_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False
        )
        .sign(root_key, hashes.SHA256())
    )

    signer_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CR"),
            x509.NameAttribute(NameOID.COMMON_NAME, "FIRMANTE PRUEBA"),
        ]
    )
    signer_cert = (
        x509.CertificateBuilder()
        .subject_name(signer_name)
        .issuer_name(root_name)
        .public_key(signer_key.public_key())
        .serial_number(3003)
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(signer_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False
        )
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(DEAD_HTTP_URL)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(DEAD_HTTP_URL),
                    )
                ]
            ),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    return {
        "root": root_cert,
        "tsa": tsa_cert,
        "signer": signer_cert,
        "root_der": _der(root_cert),
        "tsa_der": _der(tsa_cert),
        "signer_der": _der(signer_cert),
        "root_key": root_key,
        "tsa_key": tsa_key,
        "signer_key": signer_key,
    }


def build_crl(
    pki: Dict[str, Any],
    last_update: Optional[datetime] = None,
    next_update: Optional[datetime] = None,
    revoked_serials: Iterable[int] = (),
) -> bytes:
    """CRL firmada por la CA raíz de la PKI sintética."""
    now = _now()
    last_update = last_update or (now - timedelta(days=1))
    next_update = next_update or (now + timedelta(days=6))
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(pki["root"].subject)
        .last_update(last_update)
        .next_update(next_update)
    )
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(last_update)
            .build()
        )
    return builder.sign(pki["root_key"], hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def ocsp_cert_id_hashes(issuer_cert: x509.Certificate) -> Dict[str, bytes]:
    """
    Calcula los hashes de RFC 6960 §4.1.1 de forma independiente al inspector:
    SHA-1 del DER del ``Name`` del emisor y SHA-1 del valor de la clave pública.
    """
    return {
        "issuer_name_hash": hashlib.sha1(issuer_cert.subject.public_bytes()).digest(),
        "issuer_key_hash": hashlib.sha1(
            issuer_cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.PKCS1,
            )
        ).digest(),
    }


def _cert_status(status: str, revocation_time: datetime) -> ocsp.CertStatus:
    if status == "good":
        return ocsp.CertStatus.load(b"\x80\x00")  # [0] IMPLICIT NULL
    if status == "unknown":
        return ocsp.CertStatus.load(b"\x82\x00")  # [2] IMPLICIT NULL
    return ocsp.CertStatus(
        name="revoked",
        value=ocsp.RevokedInfo(
            {
                "revocation_time": revocation_time,
                "revocation_reason": "key_compromise",
            }
        ),
    )


def build_ocsp(
    pki: Dict[str, Any],
    serial: int,
    status: str = "good",
    this_update: Optional[datetime] = None,
    next_update: Optional[datetime] = None,
) -> bytes:
    """Respuesta OCSP (RFC 6960) en DER para el certificado indicado."""
    now = _now()
    this_update = this_update or now
    next_update = next_update or (now + timedelta(days=1))
    hashes = ocsp_cert_id_hashes(pki["root"])
    root_asn1 = ax509.Certificate.load(pki["root_der"])

    single = {
        "cert_id": {
            "hash_algorithm": {"algorithm": "sha1"},
            "issuer_name_hash": hashes["issuer_name_hash"],
            "issuer_key_hash": hashes["issuer_key_hash"],
            "serial_number": serial,
        },
        "cert_status": _cert_status(status, this_update - timedelta(days=2)),
        "this_update": this_update,
        "next_update": next_update,
    }
    basic = ocsp.BasicOCSPResponse(
        {
            "tbs_response_data": {
                "responder_id": {"by_name": root_asn1["tbs_certificate"]["subject"]},
                "produced_at": this_update,
                "responses": [single],
            },
            "signature_algorithm": {"algorithm": "sha256_rsa"},
            "signature": b"\x11" * 256,
            "certs": [root_asn1],
        }
    )
    return ocsp.OCSPResponse(
        {
            "response_status": "successful",
            "response_bytes": {
                "response_type": "basic_ocsp_response",
                "response": basic,
            },
        }
    ).dump()


def minimal_pdf() -> bytes:
    """PDF de una página en blanco con tabla xref clásica."""
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=595, height=842)
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def append_pdf_objects(pdf_bytes: bytes, objects: Dict[int, Any], next_free_id: int) -> bytes:
    """Anexa objetos como revisión incremental (para construir documentos «rotos» a propósito)."""
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    updated, _ = _append_incremental_revision(pdf_bytes, objects, next_free_id, reader)
    return updated


def pdf_with_root_entry(pdf_bytes: bytes, key: str, value: Any) -> bytes:
    """Añade una entrada al diccionario /Root del documento (revisión incremental)."""
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    root_ref = dict.__getitem__(reader.trailer, "/Root")
    root_obj = root_ref.get_object()
    next_id = _get_max_object_id(reader) + 1
    root_copy = DictionaryObject({k: dict.__getitem__(root_obj, k) for k in root_obj.keys()})
    root_copy[NameObject(key)] = IndirectObject(next_id, 0, reader)
    return append_pdf_objects(pdf_bytes, {next_id: value, root_ref.idnum: root_copy}, next_id + 1)


def attach_signature_field(
    pdf_bytes: bytes,
    contents: Optional[bytes] = None,
    cms_builder: Optional[Callable[[bytes], bytes]] = None,
    subfilter: bytes = b"/ETSI.CAdES.detached",
    field_name: str = "Signature1",
    buffer_bytes: int = 16384,
) -> bytes:
    """
    Añade un campo de firma a la primera página y rellena su ``/Contents``.

    Con ``cms_builder`` se recalcula el ``/ByteRange`` y se le pasa el digest del documento
    para que construya el CMS; con ``contents`` se escribe ese contenido tal cual (útil para
    documentos con firmas ilegibles).
    """
    raw_contents = contents or b""
    hex_len = max(len(raw_contents.hex()), buffer_bytes)
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    root_ref = dict.__getitem__(reader.trailer, "/Root")
    root_obj = root_ref.get_object()
    page0 = reader.pages[0]
    page0_ref = page0.indirect_reference
    next_id = _get_max_object_id(reader) + 1
    v_id, widget_id = next_id, next_id + 1

    v_bytes = (
        b"<<\n/Type /Sig\n/Filter /Adobe.PPKLite\n/SubFilter " + subfilter + b"\n"
        b"/Contents <" + raw_contents.hex().encode("ascii") + b"0" * (hex_len - len(raw_contents.hex())) + b">\n"
        + BR_PLACEHOLDER
        + b"\n>>"
    )
    widget_ref = IndirectObject(widget_id, 0, reader)
    widget = DictionaryObject(
        {
            NameObject("/FT"): NameObject("/Sig"),
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Widget"),
            NameObject("/F"): NumberObject(132),
            NameObject("/T"): TextStringObject(field_name),
            NameObject("/V"): IndirectObject(v_id, 0, reader),
            NameObject("/P"): page0_ref,
            NameObject("/Rect"): ArrayObject([NumberObject(0)] * 4),
        }
    )
    # Conservar los campos ya presentes: un documento puede tener varias firmas.
    existing_fields: list = []
    acroform_copy = DictionaryObject()
    if "/AcroForm" in root_obj:
        acroform = root_obj["/AcroForm"].get_object()
        for key in acroform.keys():
            acroform_copy[key] = dict.__getitem__(acroform, key)
        if "/Fields" in acroform:
            existing_fields = list(acroform["/Fields"].get_object())
    acroform_copy[NameObject("/Fields")] = ArrayObject(existing_fields + [widget_ref])
    acroform_copy[NameObject("/SigFlags")] = NumberObject(3)

    root_copy = DictionaryObject({k: dict.__getitem__(root_obj, k) for k in root_obj.keys()})
    root_copy[NameObject("/AcroForm")] = acroform_copy
    page0_copy = DictionaryObject({k: dict.__getitem__(page0, k) for k in page0.keys()})
    page0_copy[NameObject("/Annots")] = ArrayObject([widget_ref])

    skeleton, offsets = _append_incremental_revision(
        pdf_bytes,
        {v_id: v_bytes, widget_id: widget, root_ref.idnum: root_copy, page0_ref.idnum: page0_copy},
        widget_id + 1,
        reader,
    )
    out = bytearray(skeleton)
    v_start = offsets[v_id] + len(f"{v_id} 0 obj\n".encode("ascii"))
    lt_pos = out.index(b"/Contents <", v_start) + len(b"/Contents ")
    gt_pos = lt_pos + 1 + hex_len
    br_pos = out.index(BR_PLACEHOLDER, v_start)

    len1 = lt_pos
    start2 = gt_pos + 1
    len2 = len(out) - start2
    br_text = f"/ByteRange [0 {len1} {start2} {len2}]"
    out[br_pos : br_pos + len(BR_PLACEHOLDER)] = (
        br_text[:-1] + (" " * (len(BR_PLACEHOLDER) - len(br_text))) + "]"
    ).encode("ascii")

    if cms_builder is not None:
        digest = hashlib.sha256(out[0:len1] + out[start2 : start2 + len2]).digest()
        built = cms_builder(digest)
        assert len(built.hex()) <= hex_len, "el contenedor CMS no cabe en el búfer reservado"
        out[lt_pos + 1 : lt_pos + 1 + len(built.hex())] = built.hex().encode("ascii")
    return bytes(out)


def build_signature_cms(
    pki: Dict[str, Any],
    digest: bytes,
    extra_certs: Sequence[bytes] = (),
    sid_serial: Optional[int] = None,
    use_ski: bool = False,
    signer_infos: bool = True,
) -> bytes:
    """CMS SignedData (/ETSI.CAdES.detached) con atributos firmados sobre ``digest``."""
    signer_asn1 = ax509.Certificate.load(pki["signer_der"])
    certs = [signer_asn1] + [ax509.Certificate.load(extra) for extra in extra_certs]

    signed_attrs = cms.CMSAttributes(
        [
            {"type": "content_type", "values": ["data"]},
            {"type": "message_digest", "values": [digest]},
        ]
    )
    signature = pki["signer_key"].sign(signed_attrs.dump(), asym_padding.PKCS1v15(), hashes.SHA256())

    serial = sid_serial if sid_serial is not None else signer_asn1["tbs_certificate"]["serial_number"].native
    if use_ski:
        from pades_renewer.pki_inspector import _get_ski

        sid: Dict[str, Any] = {"subject_key_identifier": _get_ski(signer_asn1)}
    else:
        sid = {
            "issuer_and_serial_number": {
                "issuer": signer_asn1["tbs_certificate"]["issuer"],
                "serial_number": serial,
            }
        }

    signer_info = {
        "version": "v1",
        "sid": sid,
        "digest_algorithm": {"algorithm": "sha256"},
        "signature_algorithm": {"algorithm": "sha256_rsa"},
        "signature": signature,
        "signed_attrs": signed_attrs,
    }

    return cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": {
                "version": "v1",
                "digest_algorithms": [{"algorithm": "sha256"}],
                "encap_content_info": {"content_type": "data"},
                "certificates": certs,
                "signer_infos": [signer_info] if signer_infos else [],
            },
        }
    ).dump()


def build_tst_token(pki: Dict[str, Any], digest: bytes, algorithm: str = "sha256") -> bytes:
    """Token RFC 3161 firmado por la TSA sintética, con su cadena embebida."""
    gen_time = _now().replace(microsecond=0)
    tst_info = tsp.TSTInfo(
        {
            "version": 1,
            "policy": "2.16.188.1.1.1.1.5",
            "message_imprint": {
                "hash_algorithm": {"algorithm": algorithm},
                "hashed_message": digest,
            },
            "serial_number": 99887766,
            "gen_time": gen_time,
        }
    )
    tsa_asn1 = ax509.Certificate.load(pki["tsa_der"])
    root_asn1 = ax509.Certificate.load(pki["root_der"])
    tst_digest = hashlib.sha256(tst_info.dump()).digest()
    signed_attrs = cms.CMSAttributes(
        [
            {"type": "content_type", "values": ["1.2.840.113549.1.9.16.1.4"]},
            {"type": "message_digest", "values": [tst_digest]},
        ]
    )
    signature = pki["tsa_key"].sign(signed_attrs.dump(), asym_padding.PKCS1v15(), hashes.SHA256())
    return cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": {
                "version": "v3",
                "digest_algorithms": [{"algorithm": "sha256"}],
                "encap_content_info": {
                    "content_type": "1.2.840.113549.1.9.16.1.4",
                    "content": tst_info,
                },
                "certificates": [tsa_asn1, root_asn1],
                "signer_infos": [
                    {
                        "version": "v1",
                        "sid": {
                            "issuer_and_serial_number": {
                                "issuer": tsa_asn1["tbs_certificate"]["issuer"],
                                "serial_number": tsa_asn1["tbs_certificate"]["serial_number"],
                            }
                        },
                        "digest_algorithm": {"algorithm": "sha256"},
                        "signed_attrs": signed_attrs,
                        "signature_algorithm": {"algorithm": "sha256_rsa"},
                        "signature": signature,
                    }
                ],
            },
        }
    ).dump()


class MockTSAClient:
    """TSA local: firma tokens con la PKI sintética, sin red."""

    def __init__(self, pki: Dict[str, Any], padding_bytes: int = 0, granted: bool = True):
        self.tsa_url = "http://tsa.prueba.local/"
        self.pki = pki
        self.padding_bytes = padding_bytes
        self.granted = granted
        self.requests: list = []

    def stamp_bytes(self, data: bytes, algorithm: str = "sha256") -> TimestampResult:
        return self.request_timestamp(hashlib.new(algorithm, data).digest(), algorithm=algorithm)

    def request_timestamp(
        self, digest: bytes, algorithm: str = "sha256", cert_req: bool = True
    ) -> TimestampResult:
        self.requests.append({"digest": digest, "algorithm": algorithm, "cert_req": cert_req})
        if not self.granted:
            return TimestampResult(
                status="rejection",
                is_granted=False,
                generated_time=None,
                policy_oid=None,
                serial_number=None,
                hash_algorithm=algorithm,
                hashed_message_hex=digest.hex(),
                nonce=None,
                tsa_certificates_count=0,
                raw_token_der=None,
                raw_response_der=b"",
                error_message="Solicitud rechazada por la TSA de prueba.",
            )
        token = build_tst_token(self.pki, digest, algorithm=algorithm)
        if self.padding_bytes:
            token += b"\x00" * self.padding_bytes
        return TimestampResult(
            status="granted",
            is_granted=True,
            generated_time=_now(),
            policy_oid="2.16.188.1.1.1.1.5",
            serial_number=99887766,
            hash_algorithm=algorithm,
            hashed_message_hex=digest.hex(),
            nonce=12345,
            tsa_certificates_count=2,
            raw_token_der=token,
            raw_response_der=token,
            error_message=None,
        )


def signed_pdf(pki: Dict[str, Any], **kwargs: Any) -> bytes:
    """PDF de una página con una firma CMS válida sobre su /ByteRange."""
    return attach_signature_field(
        minimal_pdf(),
        cms_builder=lambda digest: build_signature_cms(pki, digest, **kwargs),
    )


def dss_dictionary(**entries: Any) -> DictionaryObject:
    """Diccionario /DSS con las entradas indicadas (para documentos de prueba)."""
    return DictionaryObject({NameObject(f"/{k}"): value for k, value in entries.items()})


__all__ = [
    "DEAD_HTTP_URL",
    "MockTSAClient",
    "attach_signature_field",
    "build_crl",
    "build_ocsp",
    "build_pki",
    "build_signature_cms",
    "build_tst_token",
    "dss_dictionary",
    "minimal_pdf",
    "ocsp_cert_id_hashes",
    "pdf_with_dss",
    "pdf_with_root_entry",
    "signed_pdf",
]


def pdf_with_dss(
    pdf_bytes: bytes,
    certs: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
    ocsps: Sequence[bytes] = (),
    single_ref: bool = False,
) -> bytes:
    """
    Añade un diccionario /DSS como revisión incremental.

    Con ``single_ref=True`` ``/Certs`` se escribe como una referencia suelta en lugar de un
    arreglo, que es una de las formas en que aparece un /DSS mal formado en la práctica.
    """
    from pypdf.generic import DecodedStreamObject

    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    root_ref = dict.__getitem__(reader.trailer, "/Root")
    root_obj = root_ref.get_object()
    next_id = _get_max_object_id(reader) + 1
    objects: Dict[int, Any] = {}

    def add_stream(blob: bytes) -> IndirectObject:
        nonlocal next_id
        stream = DecodedStreamObject()
        stream.set_data(blob)
        objects[next_id] = stream
        ref = IndirectObject(next_id, 0, reader)
        next_id += 1
        return ref

    cert_refs = [add_stream(blob) for blob in certs]
    crl_refs = [add_stream(blob) for blob in crls]
    ocsp_refs = [add_stream(blob) for blob in ocsps]

    dss = DictionaryObject({NameObject("/Type"): NameObject("/DSS")})
    if cert_refs:
        dss[NameObject("/Certs")] = cert_refs[0] if single_ref else ArrayObject(cert_refs)
    if crl_refs:
        dss[NameObject("/CRLs")] = ArrayObject(crl_refs)
    if ocsp_refs:
        dss[NameObject("/OCSPs")] = ArrayObject(ocsp_refs)

    dss_id = next_id
    objects[dss_id] = dss
    next_id += 1

    root_copy = DictionaryObject({k: dict.__getitem__(root_obj, k) for k in root_obj.keys()})
    root_copy[NameObject("/DSS")] = IndirectObject(dss_id, 0, reader)
    objects[root_ref.idnum] = root_copy
    return append_pdf_objects(pdf_bytes, objects, next_id)
