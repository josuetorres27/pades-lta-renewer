"""
Pruebas unitarias e de integración para:
- Inspector PKI / X.509 (`pki_inspector.py`)
- Inyector incremental PAdES-B-LT (/DSS) + PAdES-B-LTA (/DocTimeStamp) (`pdf_injector.py`)
- Interfaz web Flask (`web/app.py`)
"""

from datetime import datetime, timedelta, timezone
import hashlib
import io
import os
from pathlib import Path
import struct

from asn1crypto import cms, tsp, x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pypdf
from pypdf.generic import (
    ArrayObject,
    DecodedStreamObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    NumberObject,
    TextStringObject,
)
import pytest

from pades_renewer.pdf_injector import _append_incremental_revision, renew_pdf_to_lta
from pades_renewer.pki_inspector import inspect_pdf_public
from pades_renewer.tsa_client import TimestampResult
from pades_renewer.web import create_app


# Optional real-world sample: set PADES_REAL_PDF to the path of a signed PAdES PDF
# to run test_real_costa_rica_pdf_live_renewal. Without it the test is skipped.
_REAL_PDF_ENV = os.environ.get("PADES_REAL_PDF", "").strip()
REAL_SAMPLE_PDF = Path(_REAL_PDF_ENV) if _REAL_PDF_ENV else None


def _build_synthetic_pki():
    now = datetime.now(timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    root_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TEST PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, "CA RAIZ TEST CR"),
    ])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1001)
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    tsa_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TEST BCCR"),
        x509.NameAttribute(NameOID.COMMON_NAME, "TSA SINPE TEST"),
    ])
    tsa_cert = (
        x509.CertificateBuilder()
        .subject_name(tsa_name)
        .issuer_name(root_name)
        .public_key(tsa_key.public_key())
        .serial_number(2002)
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(tsa_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    signer_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CR"),
        x509.NameAttribute(NameOID.COMMON_NAME, "FIRMANTE EXPIRADO TEST"),
    ])
    signer_cert = (
        x509.CertificateBuilder()
        .subject_name(signer_name)
        .issuer_name(root_name)
        .public_key(signer_key.public_key())
        .serial_number(3003)
        .not_valid_before(now - timedelta(days=400))
        .not_valid_after(now - timedelta(days=5))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(signer_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    return {
        "root_der": root_cert.public_bytes(serialization.Encoding.DER),
        "tsa_der": tsa_cert.public_bytes(serialization.Encoding.DER),
        "signer_der": signer_cert.public_bytes(serialization.Encoding.DER),
        "root_key": root_key,
        "tsa_key": tsa_key,
        "signer_key": signer_key,
    }


def _build_signed_tst_token(pki, digest: bytes, algorithm: str = "sha256") -> bytes:
    gen_time = datetime.now(timezone.utc).replace(microsecond=0)
    tst_info = tsp.TSTInfo({
        "version": 1,
        "policy": "2.16.188.1.1.1.1.5",
        "message_imprint": {
            "hash_algorithm": {"algorithm": algorithm},
            "hashed_message": digest,
        },
        "serial_number": 99887766,
        "gen_time": gen_time,
    })
    tsa_asn1 = ax509.Certificate.load(pki["tsa_der"])
    root_asn1 = ax509.Certificate.load(pki["root_der"])
    tst_bytes = tst_info.dump()
    tst_digest = hashlib.sha256(tst_bytes).digest()

    signed_attrs = cms.CMSAttributes([
        {"type": "content_type", "values": ["1.2.840.113549.1.9.16.1.4"]},
        {"type": "message_digest", "values": [tst_digest]},
    ])
    sig = pki["tsa_key"].sign(
        signed_attrs.dump(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    ci = cms.ContentInfo({
        "content_type": "signed_data",
        "content": {
            "version": "v3",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {
                "content_type": "1.2.840.113549.1.9.16.1.4",
                "content": tst_info,
            },
            "certificates": [tsa_asn1, root_asn1],
            "signer_infos": [{
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
                "signature": sig,
            }],
        },
    })
    return ci.dump()


def _build_minimal_pdf(use_xref_stream: bool = False) -> bytes:
    """Genera un PDF mínimo de 1 página en memoria (classic xref o /Type /XRef stream)."""
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=595, height=842)
    buf = io.BytesIO()
    writer.write(buf)
    classic_pdf = buf.getvalue()
    if not use_xref_stream:
        return classic_pdf

    # Convertir a documento base con flujo /Type /XRef
    r = pypdf.PdfReader(io.BytesIO(classic_pdf))
    objs = []
    max_oid = 0
    for oid in sorted(r.xref[0].keys()):
        if oid == 0:
            continue
        max_oid = max(max_oid, oid)
        obj = r.get_object(oid)
        obuf = io.BytesIO()
        obj.write_to_stream(obuf)
        objs.append((oid, obuf.getvalue()))

    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for oid, obytes in objs:
        offsets[oid] = len(out)
        out.extend(f"{oid} 0 obj\n".encode("ascii"))
        out.extend(obytes)
        out.extend(b"\nendobj\n")

    xref_id = max_oid + 1
    xref_offset = len(out)
    offsets[xref_id] = xref_offset

    entries = bytearray(struct.pack(">BQH", 0, 0, 65535))
    index_arr = ArrayObject([NumberObject(0), NumberObject(1)])
    for oid in sorted(offsets.keys()):
        index_arr.append(NumberObject(oid))
        index_arr.append(NumberObject(1))
        entries.extend(struct.pack(">BQH", 1, offsets[oid], 0))

    root_ref = dict.__getitem__(r.trailer, "/Root")
    stm = DecodedStreamObject()
    stm[NameObject("/Type")] = NameObject("/XRef")
    stm[NameObject("/Size")] = NumberObject(xref_id + 1)
    stm[NameObject("/W")] = ArrayObject([NumberObject(1), NumberObject(8), NumberObject(2)])
    stm[NameObject("/Index")] = index_arr
    stm[NameObject("/Root")] = IndirectObject(root_ref.idnum, 0, r)
    stm.set_data(bytes(entries))

    sbuf = io.BytesIO()
    stm.write_to_stream(sbuf)
    out.extend(f"{xref_id} 0 obj\n".encode("ascii"))
    out.extend(sbuf.getvalue())
    out.extend(f"\nendobj\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii"))
    return bytes(out)


def _attach_synthetic_user_sig(pdf_bytes: bytes, pki) -> bytes:
    """Agrega una firma CMS (/ETSI.CAdES.detached) válida sobre ByteRange para pruebas offline."""
    from pades_renewer.pdf_injector import BR_PLACEHOLDER, _get_max_object_id

    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    root_ref = dict.__getitem__(reader.trailer, "/Root")
    root_obj = root_ref.get_object()
    p0 = reader.pages[0]
    p0_ref = p0.indirect_reference
    nid = _get_max_object_id(reader) + 1
    v_id, w_id = nid, nid + 1

    contents_hex_len = 8192
    v_bytes = (
        b"<<\n/Type /Sig\n/Filter /Adobe.PPKLite\n/SubFilter /ETSI.CAdES.detached\n"
        b"/Contents <" + (b"0" * contents_hex_len) + b">\n" + BR_PLACEHOLDER + b"\n>>"
    )
    w_ref = IndirectObject(w_id, 0, reader)
    w_dict = DictionaryObject({
        NameObject("/FT"): NameObject("/Sig"),
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Widget"),
        NameObject("/F"): NumberObject(132),
        NameObject("/T"): TextStringObject("Signature1"),
        NameObject("/V"): IndirectObject(v_id, 0, reader),
        NameObject("/P"): p0_ref,
        NameObject("/Rect"): ArrayObject([NumberObject(0)] * 4),
    })
    root_copy = DictionaryObject({k: dict.__getitem__(root_obj, k) for k in root_obj.keys()})
    root_copy[NameObject("/AcroForm")] = DictionaryObject({
        NameObject("/Fields"): ArrayObject([w_ref]),
        NameObject("/SigFlags"): NumberObject(3),
    })
    p0_copy = DictionaryObject({k: dict.__getitem__(p0, k) for k in p0.keys()})
    p0_copy[NameObject("/Annots")] = ArrayObject([w_ref])

    skel, offsets = _append_incremental_revision(
        pdf_bytes,
        {v_id: v_bytes, w_id: w_dict, root_ref.idnum: root_copy, p0_ref.idnum: p0_copy},
        w_id + 1,
        reader,
    )
    out = bytearray(skel)
    v_start = offsets[v_id] + len(f"{v_id} 0 obj\n".encode("ascii"))
    lt_pos = out.index(b"/Contents <", v_start) + len(b"/Contents ")
    gt_pos = lt_pos + 1 + contents_hex_len
    br_pos = out.index(BR_PLACEHOLDER, v_start)

    len1 = lt_pos
    start2 = gt_pos + 1
    len2 = len(out) - start2
    br_txt = f"/ByteRange [0 {len1} {start2} {len2}]"
    out[br_pos : br_pos + len(BR_PLACEHOLDER)] = (
        br_txt[:-1] + (" " * (len(BR_PLACEHOLDER) - len(br_txt))) + "]"
    ).encode("ascii")

    digest = hashlib.sha256(out[0:len1] + out[start2 : start2 + len2]).digest()
    signer_asn1 = ax509.Certificate.load(pki["signer_der"])
    signed_attrs = cms.CMSAttributes([
        {"type": "content_type", "values": ["data"]},
        {"type": "message_digest", "values": [digest]},
    ])
    sig = pki["signer_key"].sign(signed_attrs.dump(), padding.PKCS1v15(), hashes.SHA256())
    ci = cms.ContentInfo({
        "content_type": "signed_data",
        "content": {
            "version": "v1",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {"content_type": "data"},
            "certificates": [signer_asn1],
            "signer_infos": [{
                "version": "v1",
                "sid": {
                    "issuer_and_serial_number": {
                        "issuer": signer_asn1["tbs_certificate"]["issuer"],
                        "serial_number": signer_asn1["tbs_certificate"]["serial_number"],
                    }
                },
                "digest_algorithm": {"algorithm": "sha256"},
                "signed_attrs": signed_attrs,
                "signature_algorithm": {"algorithm": "sha256_rsa"},
                "signature": sig,
            }],
        },
    })
    tok_hex = ci.dump().hex().encode("ascii")
    out[lt_pos + 1 : lt_pos + 1 + len(tok_hex)] = tok_hex
    return bytes(out)


class _MockTSAClient:
    def __init__(self, pki, padding_bytes: int = 0):
        self.tsa_url = "http://mock.tsa.local/"
        self.pki = pki
        self.padding_bytes = padding_bytes

    def stamp_bytes(self, data: bytes, algorithm: str = "sha256") -> TimestampResult:
        return self.request_timestamp(hashlib.new(algorithm, data).digest(), algorithm=algorithm)

    def request_timestamp(self, digest: bytes, algorithm: str = "sha256", cert_req: bool = True) -> TimestampResult:
        tok = _build_signed_tst_token(self.pki, digest, algorithm=algorithm)
        if self.padding_bytes:
            tok = tok + (b"\x00" * self.padding_bytes)
        return TimestampResult(
            status="granted",
            is_granted=True,
            generated_time=datetime.now(timezone.utc),
            policy_oid="2.16.188.1.1.1.1.5",
            serial_number=99887766,
            hash_algorithm=algorithm,
            hashed_message_hex=digest.hex(),
            nonce=12345,
            tsa_certificates_count=2,
            raw_token_der=tok,
            raw_response_der=tok,
            error_message=None,
        )


def test_offline_renewal_classic_xref_and_branch_to_root():
    pki = _build_synthetic_pki()
    signed_pdf = _attach_synthetic_user_sig(_build_minimal_pdf(use_xref_stream=False), pki)

    pre = inspect_pdf_public(signed_pdf, fetch_remote=False)
    assert pre["pades_profile"] == "PAdES-B-B"
    assert pre["any_signer_expired"] is True
    assert pre["signatures"][0]["byterange_hash_valid"] is True

    res = renew_pdf_to_lta(signed_pdf, tsa_client=_MockTSAClient(pki))
    assert res.success is True
    assert res.original_profile == "PAdES-B-B"
    assert res.new_profile == "PAdES-B-LTA"
    assert res.field_name == "Signature2"
    assert res.dss_counts["certs"] >= 3

    post = res.post_inspection
    assert post["signatures_count"] == 2
    assert post["signatures"][0]["byterange_hash_valid"] is True
    assert post["signatures"][1]["byterange_hash_valid"] is True
    assert post["signatures"][1]["covers_whole_document"] is True

    tsa_branch = post["signatures"][1]["branches"][0]
    assert tsa_branch["reaches_root"] is True
    assert tsa_branch["chain_cryptographically_valid"] is True
    assert tsa_branch["root_common_name"] == "CA RAIZ TEST CR"

    # La cadena del firmante expirado también alcanza CA RAIZ TEST CR gracias al /DSS inyectado
    signer_branch = post["signatures"][0]["branches"][0]
    assert signer_branch["reaches_root"] is True
    assert signer_branch["nodes"][0]["validity_status"] == "vencido"
    assert "CA RAIZ TEST CR" in signer_branch["root_common_name"]


def test_offline_renewal_xref_stream_pdf():
    pki = _build_synthetic_pki()
    signed_pdf = _attach_synthetic_user_sig(_build_minimal_pdf(use_xref_stream=True), pki)

    res = renew_pdf_to_lta(signed_pdf, tsa_client=_MockTSAClient(pki))
    assert res.success is True
    assert res.new_profile == "PAdES-B-LTA"

    reader = pypdf.PdfReader(io.BytesIO(res.output_pdf_bytes))
    assert len(reader.pages) == 1
    assert "/DSS" in reader.trailer["/Root"].get_object()
    assert res.post_inspection["signatures"][1]["byterange_hash_valid"] is True
    assert res.post_inspection["signatures"][1]["covers_whole_document"] is True


def test_oversized_token_buffer_retries_cleanly():
    pki = _build_synthetic_pki()
    signed_pdf = _attach_synthetic_user_sig(_build_minimal_pdf(use_xref_stream=False), pki)

    # Forzar reintento automático reservando inicialmente solo 256 bytes
    res = renew_pdf_to_lta(signed_pdf, tsa_client=_MockTSAClient(pki), token_buffer_bytes=256)
    assert res.success is True
    assert res.post_inspection["signatures"][1]["byterange_hash_valid"] is True
    assert res.post_inspection["signatures"][1]["covers_whole_document"] is True


def test_web_app_ui_and_api_validation():
    app = create_app()
    client = app.test_client()

    home = client.get("/")
    assert home.status_code == 200
    html = home.get_data(as_text=True)
    assert '<html lang="es">' in html
    assert '<meta name="color-scheme" content="light dark"' in html
    assert 'id="dropzone"' in html
    assert 'aria-live="polite"' in html

    empty_post = client.post("/api/renew", data={})
    assert empty_post.status_code == 400

    bad_file = client.post(
        "/api/renew",
        data={"file": (io.BytesIO(b"no es un pdf"), "notas.txt")},
        content_type="multipart/form-data",
    )
    assert bad_file.status_code == 400
    assert "error" in bad_file.get_json()

    not_found = client.get("/api/download/000000000000")
    assert not_found.status_code == 404


def test_web_app_end_to_end_live_or_mocked(monkeypatch):
    pki = _build_synthetic_pki()
    signed_pdf = _attach_synthetic_user_sig(_build_minimal_pdf(use_xref_stream=False), pki)

    import pades_renewer.pdf_injector as injector_mod

    monkeypatch.setattr(injector_mod, "TSASinpeClient", lambda *a, **kw: _MockTSAClient(pki))

    app = create_app()
    client = app.test_client()

    resp = client.post(
        "/api/renew",
        data={"file": (io.BytesIO(signed_pdf), "Contrato Prueba.pdf")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["new_profile"] == "PAdES-B-LTA"
    assert data["download_name"] == "Contrato Prueba_LTA.pdf"

    dl = client.get(data["download_url"])
    assert dl.status_code == 200
    assert dl.mimetype == "application/pdf"
    assert dl.data.startswith(b"%PDF-")


@pytest.mark.skipif(
    REAL_SAMPLE_PDF is None or not REAL_SAMPLE_PDF.is_file(),
    reason="set PADES_REAL_PDF to a signed sample PDF to run this test",
)
def test_real_costa_rica_pdf_live_renewal():
    pdf_bytes = REAL_SAMPLE_PDF.read_bytes()
    res = renew_pdf_to_lta(pdf_bytes)
    assert res.success is True
    assert res.original_profile == "PAdES-B-T"
    assert res.new_profile == "PAdES-B-LTA"
    assert res.post_inspection["signatures"][0]["byterange_hash_valid"] is True
    assert res.post_inspection["signatures"][1]["byterange_hash_valid"] is True
    assert res.post_inspection["signatures"][1]["covers_whole_document"] is True
    assert res.effective_protection_until is not None

    offline = inspect_pdf_public(res.output_pdf_bytes, fetch_remote=False)
    assert offline["pades_profile"] == "PAdES-B-LTA"
    for sig in offline["signatures"]:
        for br in sig["branches"]:
            assert br["reaches_root"] is True
            assert br["chain_cryptographically_valid"] is True
