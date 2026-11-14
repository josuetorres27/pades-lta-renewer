"""
Inspector PKI / X.509 / PAdES / TSA para documentos PDF firmados digitalmente.

Extrae y valida:
- Todas las firmas (/Sig) y sellos documentales (/DocTimeStamp) de un PDF
- Integridad de /ByteRange y digest embebido
- Cadenas completas de certificados hasta la CA Raíz (usando certificados embebidos,
  /DSS y descarga dinámica vía AIA ca_issuers)
- Vigencia temporal de cada eslabón (Hoja/TSA, CA Emisora, CA Política, CA Raíz)
- Políticas de certificación (OID, explicitText, CPS), algoritmos y uso de claves
- Estado de revocación vía OCSP (RFC 6960) y CRL (RFC 5280)
- Análisis contextual del impacto de vencimiento o compromiso de la CA Raíz
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import hashlib
import io
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import pypdf
import requests
from asn1crypto import cms, crl, ocsp, pem, tsp, x509
from cryptography import x509 as cx509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa


EXPIRING_SOON_DAYS = 180


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _format_iso(dt: Optional[datetime]) -> Optional[str]:
    dt_utc = _ensure_utc(dt)
    return dt_utc.isoformat() if dt_utc else None


def _safe_url(url: str) -> str:
    """Escapa espacios en URLs heredadas de repositorios PKI sin romper el esquema."""
    url = url.strip("\x00 ").strip()
    if " " in url:
        scheme, rest = url.split("://", 1) if "://" in url else ("http", url)
        host, path = rest.split("/", 1) if "/" in rest else (rest, "")
        encoded_path = "/".join(quote(seg, safe="()_-.") for seg in path.split("/"))
        return f"{scheme}://{host}/{encoded_path}"
    return url


def _load_cert_der(raw_bytes: bytes) -> bytes:
    if pem.detect(raw_bytes):
        _, _, der_bytes = pem.unarmor(raw_bytes)
        return der_bytes
    return raw_bytes


def _get_dn_attrs(name: x509.Name) -> Dict[str, str]:
    native = name.native
    return {
        "common_name": str(native.get("common_name") or ""),
        "organization": str(native.get("organization_name") or ""),
        "organizational_unit": str(native.get("organizational_unit_name") or ""),
        "country": str(native.get("country_name") or ""),
        "serial_number_attr": str(native.get("serial_number") or ""),
    }


def _get_ski(cert: x509.Certificate) -> Optional[bytes]:
    for ext in cert["tbs_certificate"]["extensions"]:
        if ext["extn_id"].native == "key_identifier":
            return ext["extn_value"].native
    return None


def _get_aki(cert: x509.Certificate) -> Optional[bytes]:
    for ext in cert["tbs_certificate"]["extensions"]:
        if ext["extn_id"].native == "authority_key_identifier":
            val = ext["extn_value"].native
            if isinstance(val, dict):
                return val.get("key_identifier")
    return None


def _verify_cert_signature(child_der: bytes, parent_der: bytes) -> bool:
    """Verifica criptográficamente la firma de child_der con la llave pública de parent_der."""
    try:
        child = cx509.load_der_x509_certificate(child_der)
        parent = cx509.load_der_x509_certificate(parent_der)
        pub_key = parent.public_key()
        sig_hash = child.signature_hash_algorithm

        if isinstance(pub_key, rsa.RSAPublicKey):
            sig_oid = child.signature_algorithm_oid.dotted_string
            # 1.2.840.113549.1.1.10 = RSASSA-PSS
            if sig_oid == "1.2.840.113549.1.1.10":
                pub_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PSS(mgf=padding.MGF1(sig_hash), salt_length=padding.PSS.AUTO),
                    sig_hash,
                )
            else:
                pub_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    sig_hash,
                )
            return True
        if isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(sig_hash),
            )
            return True
        if isinstance(pub_key, ed25519.Ed25519PublicKey):
            pub_key.verify(child.signature, child.tbs_certificate_bytes)
            return True
    except (InvalidSignature, Exception):
        return False
    return False


def _is_self_signed(cert: x509.Certificate, cert_der: bytes) -> bool:
    tbs = cert["tbs_certificate"]
    if tbs["subject"].dump() != tbs["issuer"].dump():
        return False
    ski = _get_ski(cert)
    aki = _get_aki(cert)
    if ski is not None and aki is not None and ski != aki:
        return False
    return _verify_cert_signature(cert_der, cert_der)


class CertificatePool:
    """
    Repositorio en memoria de certificados X.509, CRLs y respuestas OCSP
    recolectados del PDF y de autoridades en línea vía HTTP (AIA/CDP/OCSP).
    """

    def __init__(
        self,
        fetch_remote: bool = True,
        timeout: int = 8,
        url_cache: Optional[Dict[str, Tuple[float, bytes]]] = None,
        url_cache_ttl: int = 600,
    ):
        self.fetch_remote = fetch_remote
        self.timeout = timeout
        self._url_cache = url_cache
        self._url_cache_ttl = url_cache_ttl
        self._certs_by_sha256: Dict[str, bytes] = {}
        self._parsed_certs: Dict[str, x509.Certificate] = {}
        self._aia_cache: Dict[str, Optional[bytes]] = {}
        self._crl_cache: Dict[str, Optional[bytes]] = {}
        self._ocsp_cache: Dict[str, Optional[bytes]] = {}

    def add_cert(self, cert_der: bytes) -> str:
        der = _load_cert_der(cert_der)
        fp = hashlib.sha256(der).hexdigest()
        if fp not in self._certs_by_sha256:
            self._certs_by_sha256[fp] = der
            self._parsed_certs[fp] = x509.Certificate.load(der)
        return fp

    def add_crl(self, crl_der: bytes, source_key: Optional[str] = None) -> None:
        key = source_key or hashlib.sha256(crl_der).hexdigest()
        if key not in self._crl_cache:
            self._crl_cache[key] = crl_der

    def add_ocsp(self, ocsp_der: bytes, source_key: Optional[str] = None) -> None:
        key = source_key or hashlib.sha256(ocsp_der).hexdigest()
        if key not in self._ocsp_cache:
            self._ocsp_cache[key] = ocsp_der
        try:
            resp = ocsp.OCSPResponse.load(ocsp_der)
            if resp["response_status"].native == "successful":
                basic = resp["response_bytes"]["response"].parsed
                if basic["certs"]:
                    for c in basic["certs"]:
                        self.add_cert(c.dump())
        except Exception:
            pass

    def all_certs_der(self) -> List[bytes]:
        return list(self._certs_by_sha256.values())

    def all_crls_der(self) -> List[bytes]:
        seen = set()
        out = []
        for val in self._crl_cache.values():
            if val:
                fp = hashlib.sha256(val).hexdigest()
                if fp not in seen:
                    seen.add(fp)
                    out.append(val)
        return out

    def all_ocsps_der(self) -> List[bytes]:
        seen = set()
        out = []
        for val in self._ocsp_cache.values():
            if val:
                fp = hashlib.sha256(val).hexdigest()
                if fp not in seen:
                    seen.add(fp)
                    out.append(val)
        return out

    def _fetch_url(self, url: str) -> Optional[bytes]:
        clean = _safe_url(url)
        if self._url_cache is not None:
            cached = self._url_cache.get(clean)
            if cached is not None:
                ts, payload = cached
                if (time.monotonic() - ts) < self._url_cache_ttl:
                    return payload
        try:
            res = requests.get(clean, timeout=self.timeout)
            if res.status_code == 200 and res.content:
                if self._url_cache is not None:
                    self._url_cache[clean] = (time.monotonic(), res.content)
                return res.content
        except requests.RequestException:
            return None
        return None

    def find_issuer(self, child_der: bytes) -> Optional[bytes]:
        child = x509.Certificate.load(child_der)
        if _is_self_signed(child, child_der):
            return None

        issuer_dump = child["tbs_certificate"]["issuer"].dump()
        aki = _get_aki(child)
        child_fp = hashlib.sha256(child_der).hexdigest()

        # 1. Buscar primero en certificados ya presentes en el pool
        candidates: List[Tuple[int, bytes]] = []
        for fp, cand in self._parsed_certs.items():
            if fp == child_fp:
                continue
            if cand["tbs_certificate"]["subject"].dump() == issuer_dump:
                cand_der = self._certs_by_sha256[fp]
                cand_ski = _get_ski(cand)
                if aki is not None and cand_ski is not None and aki != cand_ski:
                    continue
                score = 2 if (aki and cand_ski and aki == cand_ski) else 1
                candidates.append((score, cand_der))

        candidates.sort(key=lambda item: item[0], reverse=True)
        for _, cand_der in candidates:
            if _verify_cert_signature(child_der, cand_der):
                return cand_der

        # 2. Si no está en el pool y fetch_remote está activo, seguir AIA ca_issuers
        if not self.fetch_remote:
            return None

        aia_urls: List[str] = []
        for ext in child["tbs_certificate"]["extensions"]:
            if ext["extn_id"].native == "authority_information_access":
                for desc in ext["extn_value"].native:
                    if desc.get("access_method") == "ca_issuers":
                        loc = str(desc.get("access_location") or "")
                        if loc.startswith(("http://", "https://")):
                            aia_urls.append(loc)

        for url in aia_urls:
            if url not in self._aia_cache:
                raw = self._fetch_url(url)
                if raw:
                    try:
                        der = _load_cert_der(raw)
                        x509.Certificate.load(der)
                        self._aia_cache[url] = der
                        self.add_cert(der)
                    except Exception:
                        self._aia_cache[url] = None
                else:
                    self._aia_cache[url] = None

            fetched_der = self._aia_cache.get(url)
            if fetched_der and _verify_cert_signature(child_der, fetched_der):
                return fetched_der

        return None

    def query_ocsp(self, cert_der: bytes, issuer_der: bytes, ocsp_url: str) -> Optional[Dict[str, Any]]:
        cert = x509.Certificate.load(cert_der)
        issuer = x509.Certificate.load(issuer_der)
        serial = cert["tbs_certificate"]["serial_number"].native
        issuer_name_hash = hashlib.sha1(issuer["tbs_certificate"]["subject"].dump()).digest()
        key_octets = issuer["tbs_certificate"]["subject_public_key_info"]["public_key"].parsed.dump()
        issuer_key_hash = hashlib.sha1(key_octets).digest()
        cache_key = f"{ocsp_url}::{hashlib.sha256(issuer_der).hexdigest()[:12]}::{serial}"

        if cache_key not in self._ocsp_cache and self._url_cache is not None:
            cached_ocsp = self._url_cache.get(cache_key)
            if cached_ocsp is not None:
                ts_c, payload_c = cached_ocsp
                if (time.monotonic() - ts_c) < min(self._url_cache_ttl, 300):
                    self.add_ocsp(payload_c, source_key=cache_key)

        if cache_key not in self._ocsp_cache and self.fetch_remote:
            try:
                req = ocsp.OCSPRequest({
                    "tbs_request": {
                        "request_list": [{
                            "req_cert": {
                                "hash_algorithm": {"algorithm": "sha1"},
                                "issuer_name_hash": issuer_name_hash,
                                "issuer_key_hash": issuer_key_hash,
                                "serial_number": serial,
                            }
                        }]
                    }
                })
                res = requests.post(
                    _safe_url(ocsp_url),
                    data=req.dump(),
                    headers={"Content-Type": "application/ocsp-request"},
                    timeout=self.timeout,
                )
                if res.status_code == 200 and res.content:
                    parsed = ocsp.OCSPResponse.load(res.content)
                    if parsed["response_status"].native == "successful":
                        self.add_ocsp(res.content, source_key=cache_key)
                        if self._url_cache is not None:
                            self._url_cache[cache_key] = (time.monotonic(), res.content)
                    else:
                        self._ocsp_cache[cache_key] = None
                else:
                    self._ocsp_cache[cache_key] = None
            except Exception:
                self._ocsp_cache[cache_key] = None

        candidates = []
        if cache_key in self._ocsp_cache:
            candidates.append((self._ocsp_cache.get(cache_key), ocsp_url))
        elif not self.fetch_remote:
            # Buscar dentro de respuestas OCSP embebidas en el PDF (/DSS)
            for val in self._ocsp_cache.values():
                if val:
                    candidates.append((val, "Embebido (/DSS)"))

        for raw_ocsp, src_label in candidates:
            if not raw_ocsp:
                continue
            try:
                parsed = ocsp.OCSPResponse.load(raw_ocsp)
                if parsed["response_status"].native != "successful":
                    continue
                basic = parsed["response_bytes"]["response"].parsed
                for single in basic["tbs_response_data"]["responses"]:
                    cid = single["cert_id"]
                    if (
                        cid["serial_number"].native == serial
                        and cid["issuer_name_hash"].native == issuer_name_hash
                        and cid["issuer_key_hash"].native == issuer_key_hash
                    ):
                        cstatus = single["cert_status"].name
                        rev_time = None
                        rev_reason = None
                        if cstatus == "revoked":
                            rev_info = single["cert_status"].chosen
                            rev_time = _format_iso(rev_info["revocation_time"].native)
                            if rev_info["revocation_reason"]:
                                rev_reason = str(rev_info["revocation_reason"].native)
                        return {
                            "status": cstatus,
                            "method": "OCSP",
                            "this_update": _format_iso(single["this_update"].native),
                            "next_update": _format_iso(single["next_update"].native) if single["next_update"] else None,
                            "revocation_time": rev_time,
                            "revocation_reason": rev_reason,
                            "source_url": src_label,
                            "der_bytes": raw_ocsp,
                        }
            except Exception:
                continue
        return None

    def query_crl(self, cert_der: bytes, crl_urls: List[str]) -> Optional[Dict[str, Any]]:
        cert = x509.Certificate.load(cert_der)
        serial = cert["tbs_certificate"]["serial_number"].native
        issuer_dump = cert["tbs_certificate"]["issuer"].dump()

        candidates: List[Tuple[bytes, str]] = []
        for url in crl_urls:
            if url not in self._crl_cache and self.fetch_remote:
                raw = self._fetch_url(url)
                if raw:
                    try:
                        if pem.detect(raw):
                            _, _, raw = pem.unarmor(raw)
                        crl.CertificateList.load(raw)
                        self._crl_cache[url] = raw
                    except Exception:
                        self._crl_cache[url] = None
                else:
                    self._crl_cache[url] = None

            raw_crl = self._crl_cache.get(url)
            if raw_crl:
                candidates.append((raw_crl, url))

        if not candidates and not self.fetch_remote:
            for val in self._crl_cache.values():
                if val:
                    candidates.append((val, "Embebido (/DSS)"))

        for raw_crl, src_label in candidates:
            try:
                crl_obj = crl.CertificateList.load(raw_crl)
                tbs = crl_obj["tbs_cert_list"]
                if tbs["issuer"].dump() != issuer_dump:
                    continue
                revoked_list = tbs["revoked_certificates"]
                rev_entry = None
                if revoked_list:
                    for entry in revoked_list:
                        if entry["user_certificate"].native == serial:
                            rev_entry = entry
                            break

                status = "revoked" if rev_entry is not None else "good"
                rev_time = None
                if rev_entry is not None:
                    rev_time = _format_iso(rev_entry["revocation_date"].native)

                return {
                    "status": status,
                    "method": "CRL",
                    "this_update": _format_iso(tbs["this_update"].native),
                    "next_update": _format_iso(tbs["next_update"].native) if tbs["next_update"] else None,
                    "revocation_time": rev_time,
                    "revocation_reason": None,
                    "source_url": src_label,
                    "entries_count": len(revoked_list) if revoked_list else 0,
                    "der_bytes": raw_crl,
                }
            except Exception:
                continue
        return None


def parse_certificate_details(
    cert_der: bytes,
    reference_time: Optional[datetime] = None,
    role_hint: Optional[str] = None,
) -> Dict[str, Any]:
    """Extrae metadatos X.509 completos de un certificado DER."""
    now = _ensure_utc(reference_time) or datetime.now(timezone.utc)
    cert = x509.Certificate.load(cert_der)
    tbs = cert["tbs_certificate"]

    subject_attrs = _get_dn_attrs(tbs["subject"])
    issuer_attrs = _get_dn_attrs(tbs["issuer"])

    not_before = _ensure_utc(tbs["validity"]["not_before"].native)
    not_after = _ensure_utc(tbs["validity"]["not_after"].native)
    days_remaining = int((not_after - now).total_seconds() // 86400) if not_after else 0

    if not_after and now > not_after:
        validity_status = "vencido"
    elif not_before and now < not_before:
        validity_status = "no_vigente_aun"
    elif days_remaining <= EXPIRING_SOON_DAYS:
        validity_status = "proximo_a_vencer"
    else:
        validity_status = "vigente"

    is_ca = False
    path_len = None
    key_usage: List[str] = []
    extended_key_usage: List[str] = []
    policies: List[Dict[str, Any]] = []
    aia_ca_issuers: List[str] = []
    ocsp_urls: List[str] = []
    crl_urls: List[str] = []

    for ext in tbs["extensions"]:
        eid = ext["extn_id"].native
        if eid == "basic_constraints":
            val = ext["extn_value"].native
            is_ca = bool(val.get("ca"))
            path_len = val.get("path_len_constraint")
        elif eid == "key_usage":
            key_usage = sorted(str(x) for x in ext["extn_value"].native)
        elif eid == "extended_key_usage":
            extended_key_usage = [str(x) for x in ext["extn_value"].native]
        elif eid == "certificate_policies":
            for pol in ext["extn_value"].native:
                oid = str(pol.get("policy_identifier") or "")
                texts = []
                cps_urls = []
                for q in pol.get("policy_qualifiers") or []:
                    qid = q.get("policy_qualifier_id")
                    qval = q.get("qualifier")
                    if qid == "user_notice" and isinstance(qval, dict):
                        txt = str(qval.get("explicit_text") or "").strip("\x00 ")
                        if txt:
                            texts.append(txt)
                    elif qid == "certification_practice_statement" and qval:
                        cps_urls.append(str(qval).strip("\x00 "))
                policies.append({
                    "oid": oid,
                    "explicit_text": " / ".join(texts) if texts else None,
                    "cps_urls": cps_urls,
                })
        elif eid == "authority_information_access":
            for desc in ext["extn_value"].native:
                method = desc.get("access_method")
                loc = str(desc.get("access_location") or "").strip("\x00 ")
                if method == "ca_issuers" and loc:
                    aia_ca_issuers.append(loc)
                elif method == "ocsp" and loc:
                    ocsp_urls.append(loc)
        elif eid == "crl_distribution_points":
            for dp in ext["extn_value"].native:
                pts = dp.get("distribution_point") or []
                for pt in pts:
                    clean_pt = str(pt).strip("\x00 ")
                    if clean_pt:
                        crl_urls.append(clean_pt)

    # Información de clave pública y algoritmo de firma
    key_alg = tbs["subject_public_key_info"]["algorithm"]["algorithm"].native
    key_bits = None
    try:
        c_cert = cx509.load_der_x509_certificate(cert_der)
        pub = c_cert.public_key()
        if hasattr(pub, "key_size"):
            key_bits = pub.key_size
    except Exception:
        pass

    sig_alg = cert["signature_algorithm"]["algorithm"].native
    self_signed = _is_self_signed(cert, cert_der)

    # Inferir rol legible dentro de la jerarquía PKI
    if self_signed and is_ca:
        role = "ca_raiz"
        role_label = "CA Raíz (Ancla de confianza)"
    elif role_hint == "tsa" or ("time_stamping" in extended_key_usage and not is_ca):
        role = "tsa"
        role_label = "Autoridad de Estampado de Tiempo (TSA)"
    elif not is_ca:
        role = role_hint or "firmante"
        role_label = "Certificado del Firmante"
    elif "politica" in subject_attrs["common_name"].lower():
        role = "ca_politica"
        role_label = "CA de Política (Intermedia)"
    elif is_ca:
        role = "ca_emisora"
        role_label = "CA Emisora (Intermedia)"
    else:
        role = "desconocido"
        role_label = "Certificado"

    serial_int = tbs["serial_number"].native

    return {
        "common_name": subject_attrs["common_name"] or tbs["subject"].human_friendly,
        "organization": subject_attrs["organization"],
        "organizational_unit": subject_attrs["organizational_unit"],
        "country": subject_attrs["country"],
        "subject_serial_id": subject_attrs["serial_number_attr"],
        "subject_dn": tbs["subject"].human_friendly,
        "issuer_dn": tbs["issuer"].human_friendly,
        "issuer_common_name": issuer_attrs["common_name"] or tbs["issuer"].human_friendly,
        "serial_number_dec": str(serial_int),
        "serial_number_hex": hex(serial_int),
        "not_before": _format_iso(not_before),
        "not_after": _format_iso(not_after),
        "days_remaining": days_remaining,
        "validity_status": validity_status,
        "is_ca": is_ca,
        "path_len_constraint": path_len,
        "is_self_signed": self_signed,
        "role": role,
        "role_label": role_label,
        "key_algorithm": str(key_alg).upper(),
        "key_size_bits": key_bits,
        "signature_algorithm": str(sig_alg),
        "key_usage": key_usage,
        "extended_key_usage": extended_key_usage,
        "policies": policies,
        "aia_ca_issuers": aia_ca_issuers,
        "ocsp_urls": ocsp_urls,
        "crl_urls": crl_urls,
        "sha256_fingerprint": hashlib.sha256(cert_der).hexdigest(),
        "sha1_fingerprint": hashlib.sha1(cert_der).hexdigest(),
    }


def _explain_node_impact(node: Dict[str, Any], branch_kind: str) -> str:
    """
    Explica qué ocurre en la verificación cuando este eslabón vence o falla,
    particularmente qué sucede cuando muere la CA Raíz o una TSA/CA intermedia.
    """
    role = node["role"]
    cn = node["common_name"]
    not_after_short = (node["not_after"] or "")[:10]
    status = node["validity_status"]

    if role == "ca_raiz":
        if status == "vencido":
            return (
                f"La CA Raíz ({cn}) expiró el {not_after_short}. Toda la rama de certificación "
                "que depende de ella pierde confianza criptográfica vigente; la preservación solo "
                "sobrevive si el documento recibió antes un sello de tiempo bajo una nueva raíz activa."
            )
        return (
            f"Ancla superior vigente hasta el {not_after_short}. Si esta CA Raíz vence o es "
            "comprometida en el futuro, todas las CA de Política, CA Emisoras y TSA que cuelgan de "
            "esta rama dejan de poder emitir o respaldar confianza por sí mismas. En PAdES-B-LTA, el "
            "re-sellado previo con una nueva TSA anclada a una raíz sucesora encapsula el hash de "
            "esta rama y preserva la validez probatoria indefinidamente."
        )

    if role in ("ca_politica", "ca_emisora"):
        if status == "vencido":
            return (
                f"Esta CA intermedia ({cn}) expiró el {not_after_short}. Sin evidencias LTV (/DSS) y "
                "una estampa de tiempo emitida antes de su vencimiento, los validadores rechazan toda "
                "firma emitida bajo esta autoridad."
            )
        return (
            f"Autoridad intermedia vigente hasta el {not_after_short}. Si expira o es revocada antes "
            "de que exista un sello de archivo actualizado (PAdES-B-LTA), la ruta hacia la CA Raíz "
            "se rompe para validaciones futuras."
        )

    if role == "tsa":
        if status == "vencido":
            return (
                f"El certificado de esta TSA ({cn}) expiró el {not_after_short}. Su sello ya no "
                "garantiza preservación futura por sí solo; requiere inyección de un nuevo DocTimeStamp "
                "emitido por una TSA vigente."
            )
        return (
            f"La TSA ({cn}) respalda la existencia temporal del documento hasta el {not_after_short}. "
            "Antes de esa fecha límite (o si sus algoritmos hash/firma se debilitan), se debe aplicar "
            "una renovación incremental PAdES-B-LTA con una TSA activa."
        )

    # Firmante hoja
    if status == "vencido":
        return (
            f"El certificado del firmante expiró el {not_after_short}. La firma conserva su validez "
            "jurídica únicamente si se demuestra mediante evidencias LTV (/DSS) y un sello de tiempo "
            "válido que no estaba revocado ni vencido en el instante en que se firmó."
        )
    return (
        f"Certificado del firmante vigente hasta el {not_after_short}. Al incorporar evidencias "
        "LTV y sellado PAdES-B-LTA desde ahora, la firma seguirá siendo verificable incluso después "
        "de que este certificado personal expire."
    )


def build_chain_to_root(
    leaf_der: bytes,
    pool: CertificatePool,
    role_hint: str = "firmante",
    reference_time: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Construye la rama completa desde el certificado hoja (Firmante o TSA) hasta la CA Raíz,
    verificando firmas de cada eslabón y consultando revocación OCSP/CRL.
    """
    now = _ensure_utc(reference_time) or datetime.now(timezone.utc)
    raw_chain: List[bytes] = []
    seen_fps = set()

    current_der: Optional[bytes] = _load_cert_der(leaf_der)
    pool.add_cert(current_der)

    while current_der is not None:
        fp = hashlib.sha256(current_der).hexdigest()
        if fp in seen_fps:
            break
        seen_fps.add(fp)
        raw_chain.append(current_der)

        cert_obj = x509.Certificate.load(current_der)
        if _is_self_signed(cert_obj, current_der):
            break
        current_der = pool.find_issuer(current_der)

    nodes: List[Dict[str, Any]] = []
    chain_crypto_valid = True

    for idx, c_der in enumerate(raw_chain):
        hint = role_hint if idx == 0 else None
        info = parse_certificate_details(c_der, reference_time=now, role_hint=hint)

        parent_der = raw_chain[idx + 1] if idx + 1 < len(raw_chain) else None
        if info["is_self_signed"]:
            sig_ok = _verify_cert_signature(c_der, c_der)
        elif parent_der is not None:
            sig_ok = _verify_cert_signature(c_der, parent_der)
        else:
            sig_ok = False
            chain_crypto_valid = False

        if not sig_ok:
            chain_crypto_valid = False
        info["signature_verified"] = sig_ok

        # Revisar revocación
        rev_info: Dict[str, Any] = {
            "status": "not_applicable" if info["is_self_signed"] else "not_checked",
            "method": None,
            "this_update": None,
            "next_update": None,
            "revocation_time": None,
            "source_url": None,
        }

        if not info["is_self_signed"] and parent_der is not None:
            ocsp_res = None
            for o_url in info["ocsp_urls"]:
                ocsp_res = pool.query_ocsp(c_der, parent_der, o_url)
                if ocsp_res is not None:
                    break
            crl_res = pool.query_crl(c_der, info["crl_urls"]) if info["crl_urls"] else None

            chosen = ocsp_res or crl_res
            if chosen:
                rev_info = {k: v for k, v in chosen.items() if k != "der_bytes"}
                if ocsp_res and crl_res:
                    rev_info["crl_also_checked"] = True
                    rev_info["crl_status"] = crl_res["status"]

        info["revocation"] = rev_info
        info["impact_explanation"] = _explain_node_impact(info, role_hint)
        nodes.append(info)

    # Propagar texto descriptivo / CPS de políticas definidas en CAs superiores a nodos hijo
    oid_meta: Dict[str, Dict[str, Any]] = {}
    for n in reversed(nodes):
        for pol in n.get("policies", []):
            oid = pol.get("oid")
            if not oid:
                continue
            entry = oid_meta.setdefault(oid, {"explicit_text": None, "cps_urls": []})
            if pol.get("explicit_text") and not entry["explicit_text"]:
                entry["explicit_text"] = pol["explicit_text"]
            for u in pol.get("cps_urls") or []:
                if u not in entry["cps_urls"]:
                    entry["cps_urls"].append(u)
    for n in nodes:
        for pol in n.get("policies", []):
            ref = oid_meta.get(pol.get("oid") or "")
            if ref:
                if not pol.get("explicit_text") and ref["explicit_text"]:
                    pol["explicit_text"] = ref["explicit_text"]
                if not pol.get("cps_urls") and ref["cps_urls"]:
                    pol["cps_urls"] = list(ref["cps_urls"])

    reaches_root = bool(nodes and nodes[-1]["is_self_signed"])
    earliest_expiry_active = None
    active_dates = [n["not_after"] for n in nodes if n["validity_status"] != "vencido" and n["not_after"]]
    if active_dates:
        earliest_expiry_active = min(active_dates)

    return {
        "branch_type": role_hint,
        "reaches_root": reaches_root,
        "chain_cryptographically_valid": chain_crypto_valid and reaches_root,
        "length": len(nodes),
        "earliest_active_expiry": earliest_expiry_active,
        "root_common_name": nodes[-1]["common_name"] if reaches_root else None,
        "nodes": nodes,
    }


def _match_signer_cert(signed_data: cms.SignedData, sid: cms.SignerIdentifier) -> Optional[bytes]:
    if not signed_data["certificates"]:
        return None
    for c in signed_data["certificates"]:
        cand = c.chosen
        if sid.name == "issuer_and_serial_number":
            if (
                cand["tbs_certificate"]["serial_number"].native == sid.chosen["serial_number"].native
                and cand["tbs_certificate"]["issuer"].dump() == sid.chosen["issuer"].dump()
            ):
                return cand.dump()
        elif sid.name == "subject_key_identifier":
            if _get_ski(cand) == sid.chosen.native:
                return cand.dump()
    return signed_data["certificates"][0].chosen.dump()


def _extract_tst_details(token_content_info: cms.ContentInfo, pool: CertificatePool) -> Dict[str, Any]:
    """Extrae metadatos del TSTInfo y certificados de una estampa RFC 3161."""
    signed_data = token_content_info["content"]
    if signed_data["certificates"]:
        for c in signed_data["certificates"]:
            pool.add_cert(c.chosen.dump())

    encap = signed_data["encap_content_info"]
    tst_info = tsp.TSTInfo.load(encap["content"].parsed.dump())
    gen_time = _ensure_utc(tst_info["gen_time"].native)

    tsa_cert_der = None
    if signed_data["certificates"] and signed_data["signer_infos"]:
        tsa_cert_der = _match_signer_cert(signed_data, signed_data["signer_infos"][0]["sid"])

    return {
        "gen_time_utc": _format_iso(gen_time),
        "gen_time_cr": (gen_time.astimezone(timezone(timedelta(hours=-6))).strftime("%Y-%m-%d %H:%M:%S (UTC-6)"))
        if gen_time
        else None,
        "policy_oid": str(tst_info["policy"].native),
        "serial_number": str(tst_info["serial_number"].native),
        "hash_algorithm": str(tst_info["message_imprint"]["hash_algorithm"]["algorithm"].native),
        "hashed_message_hex": tst_info["message_imprint"]["hashed_message"].native.hex(),
        "tsa_cert_der": tsa_cert_der,
    }


def _compute_byterange_hash(pdf_bytes: bytes, byte_range: List[int], hash_alg: str) -> Optional[bytes]:
    if not byte_range or len(byte_range) != 4:
        return None
    start1, len1, start2, len2 = [int(x) for x in byte_range]
    if start1 < 0 or len1 < 0 or start2 < 0 or len2 < 0:
        return None
    if start2 + len2 > len(pdf_bytes):
        return None
    data = pdf_bytes[start1 : start1 + len1] + pdf_bytes[start2 : start2 + len2]
    try:
        h = hashlib.new(hash_alg)
        h.update(data)
        return h.digest()
    except Exception:
        return None


def inspect_pdf(
    pdf_bytes: bytes,
    fetch_remote: bool = True,
    url_cache: Optional[Dict[str, Tuple[float, bytes]]] = None,
) -> Dict[str, Any]:
    """
    Analiza un documento PDF firmado digitalmente:
    - Detecta todas las firmas y sellos DocTimeStamp
    - Verifica hashes /ByteRange
    - Inspecciona el diccionario /DSS existente
    - Construye todas las ramas completas hasta la CA Raíz (firmante + TSAs)
    - Determina el perfil PAdES actual (B-B, B-T, B-LT, B-LTA) y la necesidad de renovación
    """
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    pool = CertificatePool(fetch_remote=fetch_remote, url_cache=url_cache)

    root = reader.trailer["/Root"].get_object()
    has_dss = "/DSS" in root
    dss_summary = {"present": False, "certs_count": 0, "crls_count": 0, "ocsps_count": 0}

    if has_dss:
        dss = root["/DSS"].get_object()
        certs_arr = dss.get("/Certs") or []
        crls_arr = dss.get("/CRLs") or []
        ocsps_arr = dss.get("/OCSPs") or []
        for ref in certs_arr:
            try:
                pool.add_cert(ref.get_object().get_data())
            except Exception:
                pass
        for ref in crls_arr:
            try:
                pool.add_crl(ref.get_object().get_data())
            except Exception:
                pass
        for ref in ocsps_arr:
            try:
                pool.add_ocsp(ref.get_object().get_data())
            except Exception:
                pass
        dss_summary = {
            "present": True,
            "certs_count": len(certs_arr),
            "crls_count": len(crls_arr),
            "ocsps_count": len(ocsps_arr),
        }

    fields = reader.get_fields() or {}
    sig_entries: List[Tuple[int, str, Dict[str, Any]]] = []
    for fname, fref in fields.items():
        fobj = fref.get_object()
        if "/V" in fobj:
            vobj = fobj["/V"].get_object()
            br = [int(x) for x in vobj.get("/ByteRange", [])] if "/ByteRange" in vobj else []
            order_key = br[1] if len(br) >= 2 else 0
            sig_entries.append((order_key, str(fname), vobj))

    sig_entries.sort(key=lambda item: item[0])

    signatures_out: List[Dict[str, Any]] = []
    has_timestamp = False
    has_doctimestamp = False
    now = datetime.now(timezone.utc)

    for _, field_name, vobj in sig_entries:
        sig_type = str(vobj.get("/Type") or "/Sig")
        subfilter = str(vobj.get("/SubFilter") or "")
        filter_name = str(vobj.get("/Filter") or "")
        byte_range = [int(x) for x in vobj.get("/ByteRange", [])] if "/ByteRange" in vobj else []
        raw_contents = bytes(vobj.get("/Contents") or b"")
        if not raw_contents:
            continue
        claimed_date = str(vobj.get("/M") or "") or None
        reason = str(vobj.get("/Reason") or "") or None

        info = cms.ContentInfo.load(raw_contents)
        signed_data = info["content"]
        if signed_data["certificates"]:
            for c in signed_data["certificates"]:
                pool.add_cert(c.chosen.dump())

        is_doc_ts = sig_type == "/DocTimeStamp" or subfilter == "/ETSI.RFC3161"
        covers_whole_doc = bool(len(byte_range) == 4 and byte_range[0] == 0 and (byte_range[2] + byte_range[3]) == len(pdf_bytes))

        if is_doc_ts:
            has_doctimestamp = True
            has_timestamp = True
            tst_meta = _extract_tst_details(info, pool)
            computed = _compute_byterange_hash(pdf_bytes, byte_range, tst_meta["hash_algorithm"])
            hash_matches = bool(computed and computed.hex() == tst_meta["hashed_message_hex"])
            tsa_branch = (
                build_chain_to_root(tst_meta["tsa_cert_der"], pool, role_hint="tsa", reference_time=now)
                if tst_meta["tsa_cert_der"]
                else None
            )

            signatures_out.append({
                "field_name": field_name,
                "kind": "doc_timestamp",
                "type": sig_type,
                "subfilter": subfilter,
                "filter": filter_name,
                "byte_range": byte_range,
                "covers_whole_document": covers_whole_doc,
                "byterange_hash_valid": hash_matches,
                "timestamp": {k: v for k, v in tst_meta.items() if k != "tsa_cert_der"},
                "branches": [tsa_branch] if tsa_branch else [],
            })
        else:
            signer_info = signed_data["signer_infos"][0]
            digest_alg = str(signer_info["digest_algorithm"]["algorithm"].native)
            computed = _compute_byterange_hash(pdf_bytes, byte_range, digest_alg)

            msg_digest_attr = None
            if signer_info["signed_attrs"]:
                for attr in signer_info["signed_attrs"]:
                    if attr["type"].native == "message_digest":
                        msg_digest_attr = attr["values"][0].native
                        break
            hash_matches = bool(computed and msg_digest_attr and computed == msg_digest_attr)

            # Ubicar certificado del firmante
            signer_cert_der = _match_signer_cert(signed_data, signer_info["sid"])

            branches: List[Dict[str, Any]] = []
            if signer_cert_der:
                branches.append(build_chain_to_root(signer_cert_der, pool, role_hint="firmante", reference_time=now))

            # Verificar si tiene estampa de tiempo embebida (signature_time_stamp_token)
            embedded_tst_meta = None
            if signer_info["unsigned_attrs"]:
                for attr in signer_info["unsigned_attrs"]:
                    if attr["type"].native == "signature_time_stamp_token":
                        has_timestamp = True
                        tst_ci = cms.ContentInfo.load(attr["values"][0].dump())
                        embedded_tst_meta = _extract_tst_details(tst_ci, pool)
                        if embedded_tst_meta["tsa_cert_der"]:
                            branches.append(
                                build_chain_to_root(
                                    embedded_tst_meta["tsa_cert_der"],
                                    pool,
                                    role_hint="tsa",
                                    reference_time=now,
                                )
                            )
                        embedded_tst_meta = {k: v for k, v in embedded_tst_meta.items() if k != "tsa_cert_der"}
                        break

            signatures_out.append({
                "field_name": field_name,
                "kind": "signature",
                "type": sig_type,
                "subfilter": subfilter,
                "filter": filter_name,
                "claimed_date": claimed_date,
                "reason": reason,
                "digest_algorithm": digest_alg,
                "byte_range": byte_range,
                "covers_whole_document": covers_whole_doc,
                "byterange_hash_valid": hash_matches,
                "embedded_timestamp": embedded_tst_meta,
                "branches": branches,
            })

    # Clasificar perfil PAdES detectado
    user_sigs_count = sum(1 for s in signatures_out if s["kind"] == "signature")
    if not signatures_out:
        pades_profile = "Sin firma"
    elif user_sigs_count == 0 and has_doctimestamp:
        pades_profile = "Sellado temporal (RFC 3161)"
    elif has_doctimestamp and dss_summary["present"]:
        pades_profile = "PAdES-B-LTA"
    elif dss_summary["present"]:
        pades_profile = "PAdES-B-LT"
    elif has_timestamp:
        pades_profile = "PAdES-B-T"
    else:
        pades_profile = "PAdES-B-B"

    # Calcular vigencia de protección temporal máxima activa (último DocTimeStamp o TSA)
    tsa_expiries: List[str] = []
    any_signer_expired = False
    for sig in signatures_out:
        for br in sig.get("branches", []):
            if br["branch_type"] == "firmante" and br["nodes"]:
                if br["nodes"][0]["validity_status"] == "vencido":
                    any_signer_expired = True
            if br["branch_type"] == "tsa" and br["nodes"]:
                tsa_node = br["nodes"][0]
                if tsa_node["validity_status"] != "vencido" and br["earliest_active_expiry"]:
                    tsa_expiries.append(br["earliest_active_expiry"])

    effective_protection_until = max(tsa_expiries) if tsa_expiries else None

    return {
        "pdf_header": reader.pdf_header,
        "file_size_bytes": len(pdf_bytes),
        "pages_count": len(reader.pages),
        "signatures_count": len(signatures_out),
        "pades_profile": pades_profile,
        "dss": dss_summary,
        "any_signer_expired": any_signer_expired,
        "effective_protection_until": effective_protection_until,
        "signatures": signatures_out,
        "_pool": pool,
    }


def inspect_pdf_public(
    pdf_bytes: bytes,
    fetch_remote: bool = True,
    url_cache: Optional[Dict[str, Tuple[float, bytes]]] = None,
) -> Dict[str, Any]:
    """Versión serializable a JSON de inspect_pdf (sin objetos internos)."""
    report = inspect_pdf(pdf_bytes, fetch_remote=fetch_remote, url_cache=url_cache)
    report.pop("_pool", None)
    return report
