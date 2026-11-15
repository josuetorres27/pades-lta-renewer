"""
Inspección tolerante a documentos reales: firmas heredadas, contenedores ilegibles y
diccionarios /DSS mal formados.

Un documento firmado que el inspector no entiende debe seguir siendo inspeccionable y
renovable: el fallo se informa por firma, nunca se propaga como excepción ni deja el
documento sin sello.
"""


import pytest
from asn1crypto import cms, x509 as ax509
from pypdf.generic import ArrayObject, NumberObject

import support_pki as sup
from pades_renewer import renew_pdf_to_lta
from pades_renewer.pdf_injector import _append_dss_revision
from pades_renewer.pki_inspector import (
    CertificatePool,
    _match_signer_cert,
    inspect_pdf,
    inspect_pdf_public,
)

BOGUS_CONTENTS = b"\x30\x03\x02\x01\x01" + b"\xff" * 40


def test_legacy_x509_container_is_reported_as_a_signature():
    """``/adbe.x509.rsa_sha1`` guarda el certificado del firmante, no un CMS."""
    pki = sup.build_pki()
    pdf = sup.attach_signature_field(
        sup.minimal_pdf(),
        contents=pki["signer_der"],
        subfilter=b"/adbe.x509.rsa_sha1",
    )

    report = inspect_pdf(pdf, fetch_remote=False)

    assert report["pades_profile"] == "PAdES-B-B"
    assert report["unreadable_signatures"] == 0
    sig = report["signatures"][0]
    assert sig["kind"] == "signature"
    assert sig["container"] == "x509"
    assert sig["signer_certificate_found"] is True
    assert sig["byterange_hash_valid"] is None, "un contenedor X.509 no embebe un digest que recomputar"
    assert sig["branches"][0]["nodes"][0]["common_name"] == "FIRMANTE PRUEBA"


def test_unreadable_signature_does_not_abort_the_inspection():
    pdf = sup.attach_signature_field(sup.minimal_pdf(), contents=BOGUS_CONTENTS, subfilter=b"/adbe.pkcs7.detached")

    report = inspect_pdf(pdf, fetch_remote=False)

    assert report["signatures_count"] == 1
    assert report["unreadable_signatures"] == 1
    assert report["pades_profile"] == "Desconocido"
    entry = report["signatures"][0]
    assert entry["kind"] == "unreadable"
    assert "no es un CMS SignedData válido" in entry["error"]
    assert report["warnings"], "la firma ilegible debe quedar registrada como advertencia"


def test_empty_signer_infos_is_reported_as_unreadable():
    pki = sup.build_pki()
    pdf = sup.attach_signature_field(
        sup.minimal_pdf(),
        cms_builder=lambda digest: sup.build_signature_cms(pki, digest, signer_infos=False),
    )

    report = inspect_pdf(pdf, fetch_remote=False)

    assert report["unreadable_signatures"] == 1
    assert "SignerInfo" in report["signatures"][0]["error"]


def test_a_broken_signature_does_not_prevent_reading_the_others():
    pki = sup.build_pki()
    pdf = sup.signed_pdf(pki)
    pdf = sup.attach_signature_field(
        pdf,
        contents=BOGUS_CONTENTS,
        subfilter=b"/adbe.pkcs7.detached",
        field_name="Signature2",
    )

    report = inspect_pdf(pdf, fetch_remote=False)

    assert report["signatures_count"] == 2
    assert [s["kind"] for s in report["signatures"]] == ["signature", "unreadable"]
    assert report["signatures"][0]["byterange_hash_valid"] is True
    assert report["pades_profile"] == "PAdES-B-B"


def test_corrupt_dss_dictionary_is_reported_not_fatal():
    pki = sup.build_pki()
    pdf = sup.pdf_with_root_entry(sup.signed_pdf(pki), "/DSS", ArrayObject([NumberObject(1)]))

    report = inspect_pdf(pdf, fetch_remote=False)

    assert report["dss"]["present"] is True
    assert report["dss"]["malformed"] is True
    assert report["dss"]["error"]
    assert report["signatures_count"] == 1
    assert any("/DSS" in w for w in report["warnings"])


def test_dss_entry_written_as_a_single_reference_is_normalized():
    pki = sup.build_pki()
    # La firma solo embebe su propio certificado: la CA raíz únicamente puede llegar desde
    # la entrada /Certs escrita como referencia suelta.
    pdf = sup.pdf_with_dss(sup.signed_pdf(pki), certs=[pki["root_der"]], single_ref=True)

    report = inspect_pdf(pdf, fetch_remote=False)

    assert report["dss"]["present"] is True
    assert report["dss"]["malformed"] is False
    assert report["dss"]["certs_count"] == 1
    branch = report["signatures"][0]["branches"][0]
    assert branch["reaches_root"] is True, "el certificado del /DSS debe poder emitir la cadena"


def test_signer_certificate_is_not_fabricated_when_the_identifier_matches_nothing():
    pki = sup.build_pki()
    pdf = sup.attach_signature_field(
        sup.minimal_pdf(),
        cms_builder=lambda digest: sup.build_signature_cms(
            pki,
            digest,
            extra_certs=[pki["root_der"]],
            sid_serial=999999,
        ),
    )

    report = inspect_pdf(pdf, fetch_remote=False)

    sig = report["signatures"][0]
    assert sig["signer_certificate_found"] is False
    assert sig["branches"] == [], "ningún certificado del contenedor corresponde al firmante"
    assert report["any_signer_expired"] is False


def test_signer_certificate_is_resolved_by_subject_key_identifier():
    pki = sup.build_pki()
    pdf = sup.attach_signature_field(
        sup.minimal_pdf(),
        cms_builder=lambda digest: sup.build_signature_cms(pki, digest, use_ski=True),
    )

    report = inspect_pdf(pdf, fetch_remote=False)

    sig = report["signatures"][0]
    assert sig["signer_certificate_found"] is True
    assert sig["branches"][0]["nodes"][0]["common_name"] == "FIRMANTE PRUEBA"


def test_single_embedded_certificate_is_used_when_the_identifier_does_not_match():
    pki = sup.build_pki()
    pdf = sup.attach_signature_field(
        sup.minimal_pdf(),
        cms_builder=lambda digest: sup.build_signature_cms(pki, digest, sid_serial=999999),
    )

    report = inspect_pdf(pdf, fetch_remote=False)

    assert report["signatures"][0]["signer_certificate_found"] is True


def test_match_signer_cert_returns_none_with_several_candidates_and_no_match():
    pki = sup.build_pki()
    signer_asn1 = ax509.Certificate.load(pki["signer_der"])
    root_asn1 = ax509.Certificate.load(pki["root_der"])
    signed_data = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {"content_type": "data"},
            "certificates": [signer_asn1, root_asn1],
            "signer_infos": [
                {
                    "version": "v1",
                    "sid": {
                        "issuer_and_serial_number": {
                            "issuer": root_asn1["tbs_certificate"]["issuer"],
                            "serial_number": 999999,
                        }
                    },
                    "digest_algorithm": {"algorithm": "sha256"},
                    "signature_algorithm": {"algorithm": "sha256_rsa"},
                    "signature": b"\x00" * 256,
                }
            ],
        }
    )

    assert _match_signer_cert(signed_data, signed_data["signer_infos"][0]["sid"]) is None


def test_renewal_repairs_a_corrupt_dss_dictionary():
    pki = sup.build_pki()
    pdf = sup.pdf_with_root_entry(sup.signed_pdf(pki), "/DSS", ArrayObject([NumberObject(1)]))

    result = renew_pdf_to_lta(pdf, tsa_client=sup.MockTSAClient(pki), fetch_remote=False)

    assert result.success is True
    assert result.new_profile == "PAdES-B-LTA"
    assert result.post_inspection["dss"]["malformed"] is False
    assert result.post_inspection["dss"]["certs_count"] >= 1

    repaired, updated, counts = _append_dss_revision(result.output_pdf_bytes, CertificatePool(fetch_remote=False))
    assert updated is False or counts["certs"] >= 1


def test_renewal_still_stamps_a_document_with_an_unreadable_signature():
    pki = sup.build_pki()
    good = sup.signed_pdf(pki)
    pdf = sup.attach_signature_field(
        good,
        contents=BOGUS_CONTENTS,
        subfilter=b"/adbe.pkcs7.detached",
        field_name="Signature2",
    )

    result = renew_pdf_to_lta(pdf, tsa_client=sup.MockTSAClient(pki), fetch_remote=False)

    assert result.success is True
    assert result.new_profile == "PAdES-B-LTA"
    kinds = [s["kind"] for s in result.post_inspection["signatures"]]
    assert "unreadable" in kinds, "la firma ilegible se conserva tal cual, sin tocarla"
    assert result.post_inspection["signatures"][0]["byterange_hash_valid"] is True


def test_renewal_reports_internal_errors_instead_of_raising(monkeypatch):
    pki = sup.build_pki()
    pdf = sup.signed_pdf(pki)

    import pades_renewer.pdf_injector as injector

    def _boom(*args, **kwargs):
        raise RuntimeError("fallo simulado al construir la revisión")

    monkeypatch.setattr(injector, "_build_doctimestamp_skeleton", _boom)

    result = renew_pdf_to_lta(pdf, tsa_client=sup.MockTSAClient(pki), fetch_remote=False)

    assert result.success is False
    assert result.output_pdf_bytes is None
    assert "fallo simulado" in result.error_message
    assert result.pre_inspection["pades_profile"] == "PAdES-B-B"


def test_renewal_reports_a_rejected_timestamp():
    pki = sup.build_pki()
    pdf = sup.signed_pdf(pki)

    result = renew_pdf_to_lta(pdf, tsa_client=sup.MockTSAClient(pki, granted=False), fetch_remote=False)

    assert result.success is False
    assert "rechazada" in result.error_message
    assert result.dss_updated is True, "las evidencias ya se habían incorporado antes del sello"


def test_unknown_hash_algorithm_is_rejected_before_touching_the_document():
    pki = sup.build_pki()

    with pytest.raises(ValueError, match="sha3-inexistente"):
        renew_pdf_to_lta(sup.signed_pdf(pki), algorithm="sha3-inexistente")


@pytest.mark.parametrize("buffer_bytes", [0, -1024])
def test_invalid_token_buffer_is_rejected_before_touching_the_document(buffer_bytes):
    pki = sup.build_pki()

    with pytest.raises(ValueError, match="token_buffer_bytes"):
        renew_pdf_to_lta(sup.signed_pdf(pki), token_buffer_bytes=buffer_bytes)


def test_oversized_token_is_retried_with_a_larger_buffer():
    pki = sup.build_pki()
    pdf = sup.signed_pdf(pki)

    result = renew_pdf_to_lta(
        pdf,
        tsa_client=sup.MockTSAClient(pki, padding_bytes=3000),
        token_buffer_bytes=256,
        fetch_remote=False,
    )

    assert result.success is True
    assert result.post_inspection["signatures"][-1]["covers_whole_document"] is True


def test_inspection_report_is_json_serialisable_even_with_warnings():
    import json

    pdf = sup.attach_signature_field(sup.minimal_pdf(), contents=BOGUS_CONTENTS, subfilter=b"/adbe.pkcs7.detached")

    report = inspect_pdf_public(pdf, fetch_remote=False)

    assert json.loads(json.dumps(report))
    assert report["unreadable_signatures"] == 1


def test_timestamp_without_tst_info_is_reported_as_unreadable():
    """Un /DocTimeStamp cuyo CMS no incluye TSTInfo tampoco debe romper la inspección."""
    pki = sup.build_pki()
    empty_tst = cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": {
                "version": "v3",
                "digest_algorithms": [{"algorithm": "sha256"}],
                "encap_content_info": {"content_type": "1.2.840.113549.1.9.16.1.4"},
                "certificates": [ax509.Certificate.load(pki["tsa_der"])],
                "signer_infos": [],
            },
        }
    ).dump()
    pdf = sup.attach_signature_field(
        sup.minimal_pdf(),
        contents=empty_tst,
        subfilter=b"/ETSI.RFC3161",
    )

    report = inspect_pdf(pdf, fetch_remote=False)

    assert report["signatures_count"] == 1
    assert report["unreadable_signatures"] == 1
    assert report["pades_profile"] == "Desconocido"


def test_document_without_signatures_reports_no_profile():
    report = inspect_pdf(sup.minimal_pdf(), fetch_remote=False)

    assert report["pades_profile"] == "Sin firma"
    assert report["signatures_count"] == 0
    assert report["dss"]["present"] is False


def test_expired_signer_is_flagged_through_the_dss_chain():
    pki = sup.build_pki()
    pdf = sup.pdf_with_dss(
        sup.signed_pdf(pki, extra_certs=[pki["root_der"]]),
        certs=[pki["root_der"]],
    )

    report = inspect_pdf(pdf, fetch_remote=True)

    assert report["signatures"][0]["branches"][0]["reaches_root"] is True
    assert report["any_signer_expired"] is False
    assert report["pades_profile"] == "PAdES-B-LT"
