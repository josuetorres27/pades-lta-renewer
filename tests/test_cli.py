"""
Interfaz de línea de comandos ``pades-renewer``: inspección, renovación y códigos de salida.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import support_pki as sup
from pades_renewer import cli as cli_module
from pades_renewer import __version__
from pades_renewer.cli import main
from pades_renewer.pki_inspector import inspect_pdf_public


def _signed_file(tmp_path: Path, pki=None, **kwargs) -> Path:
    pki = pki or sup.build_pki()
    path = tmp_path / "contrato.pdf"
    path.write_bytes(sup.attach_signature_field(sup.minimal_pdf(), cms_builder=lambda d: sup.build_signature_cms(pki, d, **kwargs)))
    return path


def test_version_flag_exits_cleanly(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])

    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_missing_subcommand_exits_with_usage_error(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main([])

    assert excinfo.value.code == 2
    assert "usage" in capsys.readouterr().err.lower()


def test_inspect_prints_a_human_readable_report(tmp_path, capsys):
    pdf = _signed_file(tmp_path)

    assert main(["inspect", str(pdf), "--no-remote"]) == 0

    salida = capsys.readouterr().out
    assert "contrato.pdf" in salida
    assert "Perfil PAdES: PAdES-B-B" in salida
    assert "Firmas detectadas: 1" in salida
    assert "[firma]" in salida
    assert "ByteRange=correcto" in salida


def test_inspect_json_output_is_machine_readable(tmp_path, capsys):
    pdf = _signed_file(tmp_path)

    assert main(["inspect", str(pdf), "--no-remote", "--json"]) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["pades_profile"] == "PAdES-B-B"
    assert report["signatures"][0]["byterange_hash_valid"] is True
    assert report["unreadable_signatures"] == 0
    assert isinstance(report["warnings"], list)


def test_inspect_reports_unreadable_signatures_without_failing(tmp_path, capsys):
    path = tmp_path / "roto.pdf"
    path.write_bytes(
        sup.attach_signature_field(
            sup.minimal_pdf(),
            contents=b"\x30\x03\x02\x01\x01" + b"\xff" * 40,
            subfilter=b"/adbe.pkcs7.detached",
        )
    )

    assert main(["inspect", str(path), "--no-remote"]) == 0

    salida = capsys.readouterr().out
    assert "ilegible" in salida
    assert "Advertencia" in salida


def test_inspect_missing_file_fails_with_a_clear_message(tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        main(["inspect", str(tmp_path / "no-existe.pdf")])

    assert "no se encontró" in str(excinfo.value)


def test_inspect_rejects_a_non_pdf_file(tmp_path):
    path = tmp_path / "notas.txt"
    path.write_text("no es un pdf")

    with pytest.raises(SystemExit) as excinfo:
        main(["inspect", str(path)])

    assert "%PDF-" in str(excinfo.value)


def test_renew_writes_the_default_output_next_to_the_input(tmp_path, capsys, monkeypatch):
    pki = sup.build_pki()
    path = _signed_file(tmp_path, pki)
    monkeypatch.setattr(cli_module, "TSASinpeClient", lambda **kwargs: sup.MockTSAClient(pki))

    assert main(["renew", str(path), "--no-remote"]) == 0

    salida = capsys.readouterr().out
    destino = tmp_path / "contrato_LTA.pdf"
    assert destino.is_file()
    assert destino.read_bytes().startswith(b"%PDF-")
    assert "PAdES-B-B → PAdES-B-LTA" in salida


def test_renew_honours_an_explicit_output_path(tmp_path, monkeypatch):
    pki = sup.build_pki()
    path = _signed_file(tmp_path, pki)
    destino = tmp_path / "salida" / "renovado.pdf"
    monkeypatch.setattr(cli_module, "TSASinpeClient", lambda **kwargs: sup.MockTSAClient(pki))

    assert main(["renew", str(path), "-o", str(destino), "--no-remote"]) == 0
    assert destino.is_file()


def test_renew_json_reports_the_stamp(tmp_path, capsys, monkeypatch):
    pki = sup.build_pki()
    path = _signed_file(tmp_path, pki)
    monkeypatch.setattr(cli_module, "TSASinpeClient", lambda **kwargs: sup.MockTSAClient(pki))

    assert main(["renew", str(path), "--no-remote", "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["success"] is True
    assert payload["new_profile"] == "PAdES-B-LTA"
    assert payload["field_name"] == "Signature2"
    assert payload["tsa_policy_oid"] == "2.16.188.1.1.1.1.5"
    assert Path(payload["output_path"]).is_file()
    assert payload["output_size_bytes"] > 0


def test_renew_uses_the_requested_hash_algorithm(tmp_path, monkeypatch):
    pki = sup.build_pki()
    path = _signed_file(tmp_path, pki)
    client = sup.MockTSAClient(pki)
    monkeypatch.setattr(cli_module, "TSASinpeClient", lambda **kwargs: client)

    assert main(["renew", str(path), "--no-remote", "--algorithm", "sha512"]) == 0

    assert client.requests[0]["algorithm"] == "sha512"
    renovado = (tmp_path / "contrato_LTA.pdf").read_bytes()
    report = inspect_pdf_public(renovado, fetch_remote=False)
    sello = report["signatures"][-1]
    assert sello["kind"] == "doc_timestamp"
    assert sello["timestamp"]["hash_algorithm"] == "sha512"
    assert sello["byterange_hash_valid"] is True


def test_renew_returns_exit_code_one_when_the_tsa_rejects(tmp_path, capsys, monkeypatch):
    pki = sup.build_pki()
    path = _signed_file(tmp_path, pki)
    monkeypatch.setattr(cli_module, "TSASinpeClient", lambda **kwargs: sup.MockTSAClient(pki, granted=False))

    assert main(["renew", str(path), "--no-remote"]) == 1

    capturado = capsys.readouterr()
    assert "rechazada" in capturado.err
    assert not (tmp_path / "contrato_LTA.pdf").exists()


def test_renew_rejects_an_unsupported_algorithm(tmp_path):
    pki = sup.build_pki()
    path = _signed_file(tmp_path, pki)

    with pytest.raises(SystemExit) as excinfo:
        main(["renew", str(path), "--algorithm", "md5"])

    assert excinfo.value.code == 2


def test_cli_runs_as_a_module_in_a_subprocess(tmp_path):
    """El comando documentado debe funcionar sin instalar el paquete: python -m pades_renewer.cli."""
    pdf = _signed_file(tmp_path)
    repo = Path(__file__).resolve().parent.parent
    env = dict(os.environ)
    entorno_previo = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(repo / "src") + (os.pathsep + entorno_previo if entorno_previo else "")

    proc = subprocess.run(
        [sys.executable, "-m", "pades_renewer.cli", "inspect", str(pdf), "--no-remote", "--json"],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )

    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["pades_profile"] == "PAdES-B-B"
