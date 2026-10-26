"""
Pruebas unitarias y de integración para el cliente TSA-SINPE (RFC 3161).
"""

import hashlib
import pytest
from pades_renewer.tsa_client import TSASinpeClient, TimestampResult
from pades_renewer.utils import compute_hash


def test_compute_hash():
    data = b"Prueba de hash"
    digest = compute_hash(data, "sha256")
    expected = hashlib.sha256(data).digest()
    assert digest == expected
    assert len(digest) == 32


def test_build_request_structure():
    client = TSASinpeClient()
    digest = hashlib.sha256(b"mensaje de prueba").digest()
    nonce = 123456789

    req = client.build_request(digest=digest, algorithm="sha256", nonce=nonce, cert_req=True)
    assert req["version"].native in ("v1", 1)
    assert req["nonce"].native == nonce
    assert req["cert_req"].native is True
    assert req["message_imprint"]["hashed_message"].native == digest
    assert req["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha256"


def test_live_tsa_sinpe_request():
    """Prueba de integración con el servicio público en vivo de la TSA-SINPE."""
    client = TSASinpeClient()
    data = b"Integrity check for CI-0140 Software Quality"
    result = client.stamp_bytes(data, algorithm="sha256")

    assert result.is_granted is True
    assert result.status == "granted"
    assert result.policy_oid == "2.16.188.1.1.1.1.5"  # OID oficial de la Política de Sellado de Tiempo de Costa Rica
    assert result.serial_number is not None
    assert result.generated_time is not None
    assert result.raw_token_der is not None
    assert len(result.raw_token_der) > 0
    assert result.hashed_message_hex == hashlib.sha256(data).hexdigest()
