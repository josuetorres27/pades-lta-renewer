"""
Evidencia de revocación de un documento PAdES-LT.

Un documento PAdES-B-LT transporta su propio material de validación (certificados, CRL y
respuestas OCSP) precisamente para poder verificarse sin red. Estas pruebas fijan que la
evidencia embebida en ``/DSS`` se use siempre, que se marque cuando está vencida y que una
respuesta de revocación prevalidezca sobre un "no revocado" más reciente.
"""

from datetime import datetime, timedelta, timezone

import support_pki as sup
from pades_renewer.pki_inspector import CertificatePool, build_chain_to_root, inspect_pdf_public

NOW = datetime.now(timezone.utc)


def _pool(embedded_crls=(), embedded_ocsps=(), fetch_remote=True) -> CertificatePool:
    pool = CertificatePool(fetch_remote=fetch_remote)
    for blob in embedded_crls:
        pool.add_crl(blob)
    for blob in embedded_ocsps:
        pool.add_ocsp(blob)
    return pool


def test_embedded_crl_is_used_when_the_remote_fetch_fails():
    pki = sup.build_pki()
    pool = _pool(embedded_crls=[sup.build_crl(pki)])

    result = pool.query_crl(pki["signer_der"], [sup.DEAD_HTTP_URL])

    assert result is not None, "la CRL del /DSS debe seguir siendo válida si la descarga falla"
    assert result["status"] == "good"
    assert result["source_url"] == "Embebido (/DSS)"
    assert result["stale"] is False


def test_embedded_crl_is_used_when_remote_fetching_is_disabled():
    pki = sup.build_pki()
    pool = _pool(embedded_crls=[sup.build_crl(pki)], fetch_remote=False)

    result = pool.query_crl(pki["signer_der"], [sup.DEAD_HTTP_URL])

    assert result is not None
    assert result["status"] == "good"
    assert result["stale"] is False


def test_embedded_ocsp_is_used_when_the_remote_responder_is_unreachable():
    pki = sup.build_pki()
    pool = _pool(embedded_ocsps=[sup.build_ocsp(pki, 3003)])

    result = pool.query_ocsp(pki["signer_der"], pki["root_der"], sup.DEAD_HTTP_URL)

    assert result is not None, "la respuesta OCSP del /DSS debe usarse si el respondedor no responde"
    assert result["status"] == "good"
    assert result["method"] == "OCSP"
    assert result["source_url"] == "Embebido (/DSS)"
    assert result["stale"] is False


def test_ocsp_cert_id_hashes_follow_rfc6960():
    """
    El fixture calcula los hashes de CertID con ``cryptography`` (DER del Name del emisor y
    valor de la clave pública); que el inspector los encuentre demuestra que su fórmula coincide
    con RFC 6960 y no solo consigo misma.
    """
    pki = sup.build_pki()
    hashes = sup.ocsp_cert_id_hashes(pki["root"])
    pool = _pool(embedded_ocsps=[sup.build_ocsp(pki, 3003)])

    result = pool.query_ocsp(pki["signer_der"], pki["root_der"], sup.DEAD_HTTP_URL)

    assert result is not None
    assert len(hashes["issuer_name_hash"]) == 20
    assert len(hashes["issuer_key_hash"]) == 20
    assert hashes["issuer_name_hash"] != hashes["issuer_key_hash"]


def test_ocsp_response_for_another_serial_is_not_reused():
    pki = sup.build_pki()
    pool = _pool(embedded_ocsps=[sup.build_ocsp(pki, 999999)])

    result = pool.query_ocsp(pki["signer_der"], pki["root_der"], sup.DEAD_HTTP_URL)

    assert result is None


def test_stale_embedded_evidence_is_labelled_instead_of_looking_current():
    pki = sup.build_pki()
    stale_crl = sup.build_crl(
        pki,
        last_update=NOW - timedelta(days=400),
        next_update=NOW - timedelta(days=30),
    )
    pool = _pool(embedded_crls=[stale_crl])

    result = pool.query_crl(pki["signer_der"], [sup.DEAD_HTTP_URL])

    assert result is not None
    assert result["status"] == "good"
    assert result["stale"] is True
    assert result["next_update"] < NOW.isoformat()


def test_fresh_evidence_is_preferred_over_stale_evidence():
    pki = sup.build_pki()
    stale = sup.build_crl(pki, last_update=NOW - timedelta(days=90), next_update=NOW - timedelta(days=60))
    fresh = sup.build_crl(pki, last_update=NOW - timedelta(days=1), next_update=NOW + timedelta(days=7))
    pool = _pool(embedded_crls=[stale, fresh])

    result = pool.query_crl(pki["signer_der"], [sup.DEAD_HTTP_URL])

    assert result is not None
    assert result["stale"] is False
    assert result["next_update"] > NOW.isoformat()


def test_a_revocation_from_older_evidence_is_not_overridden_by_a_newer_good_one():
    pki = sup.build_pki()
    revoked = sup.build_crl(
        pki,
        last_update=NOW - timedelta(days=90),
        next_update=NOW - timedelta(days=60),
        revoked_serials=[3003],
    )
    good = sup.build_crl(pki, last_update=NOW - timedelta(days=1), next_update=NOW + timedelta(days=7))
    pool = _pool(embedded_crls=[good, revoked])

    result = pool.query_crl(pki["signer_der"], [sup.DEAD_HTTP_URL])

    assert result is not None
    assert result["status"] == "revoked", "una revocación documentada no caduca como un 'no revocado'"
    assert result["revocation_time"] is not None


def test_chain_node_reports_revocation_from_embedded_evidence():
    pki = sup.build_pki()
    pool = _pool(
        embedded_ocsps=[sup.build_ocsp(pki, 3003, status="revoked")],
        embedded_crls=[sup.build_crl(pki)],
    )
    pool.add_cert(pki["root_der"])

    branch = build_chain_to_root(pki["signer_der"], pool, role_hint="firmante", reference_time=NOW)

    node = branch["nodes"][0]
    assert branch["reaches_root"] is True
    assert node["revocation"]["status"] == "revoked"
    assert node["revocation"]["method"] == "OCSP"
    assert node["revocation"]["source_url"] == "Embebido (/DSS)"
    assert node["revocation"]["stale"] is False


def test_renewal_reuses_dss_evidence_instead_of_losing_it():
    """
    Documento PAdES-B-LT sin red: la renovación debe conservar la evidencia del /DSS y el
    informe posterior debe seguir verificando revocación con ella.
    """
    from pades_renewer import renew_pdf_to_lta

    pki = sup.build_pki()
    signed = sup.signed_pdf(pki)
    lt_document = sup.pdf_with_dss(
        signed,
        certs=[pki["signer_der"], pki["root_der"]],
        crls=[sup.build_crl(pki)],
        ocsps=[sup.build_ocsp(pki, 3003)],
    )

    pre = inspect_pdf_public(lt_document, fetch_remote=True)
    assert pre["pades_profile"] == "PAdES-B-LT"
    assert pre["signatures"][0]["branches"][0]["nodes"][0]["revocation"]["status"] == "good"

    result = renew_pdf_to_lta(lt_document, tsa_client=sup.MockTSAClient(pki), fetch_remote=True)

    assert result.success is True
    assert result.new_profile == "PAdES-B-LTA"
    post = result.post_inspection
    signer_node = post["signatures"][0]["branches"][0]["nodes"][0]
    assert signer_node["revocation"]["status"] == "good"
    assert signer_node["revocation"]["source_url"] == "Embebido (/DSS)"
    assert post["dss"]["crls_count"] >= 1
    assert post["dss"]["ocsps_count"] >= 1
