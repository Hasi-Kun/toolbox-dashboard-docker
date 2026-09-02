"""Tests fuer den Canary-/Honey-Token-Scanner. Nutzt ECHTE, strukturell
gueltige Testdateien (ZIP-Container / minimales PDF mit komprimiertem
Stream) statt Mocks -- die eigentliche Logik (ZIP-Member-Iteration,
Flate-Dekompression) laesst sich damit direkt end-to-end verifizieren.
"""

import io
import zipfile
import zlib

import pytest
from fastapi import UploadFile
from starlette.datastructures import Headers


def _make_docx_with_url(url: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
        zf.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>Text</w:body></w:document>')
        zf.writestr(
            "word/_rels/document.xml.rels",
            f'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="{url}" TargetMode="External"/></Relationships>',
        )
    return buf.getvalue()


def _make_clean_docx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
        zf.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>Normaler Text</w:body></w:document>')
    return buf.getvalue()


def _make_pdf_with_compressed_url(url: str) -> bytes:
    content_stream = f"BT /F1 12 Tf ({url}) Tj ET".encode()
    compressed = zlib.compress(content_stream)
    pdf = b"%PDF-1.4\n"
    pdf += b"1 0 obj << /Type /Catalog >> endobj\n"
    pdf += b"2 0 obj << /Length " + str(len(compressed)).encode() + b" /Filter /FlateDecode >>\n"
    pdf += b"stream\n" + compressed + b"\nendstream\nendobj\n%%EOF"
    return pdf


def _make_pdf_with_raw_url(url: str) -> bytes:
    return f"%PDF-1.4\n1 0 obj << /Type /Annot /URI ({url}) >> endobj\n%%EOF".encode()


def _upload_file(filename: str, content: bytes, content_type: str) -> UploadFile:
    return UploadFile(filename=filename, file=io.BytesIO(content), headers=Headers({"content-type": content_type}))


# --- Erkennungslogik direkt (ohne HTTP-Schicht) -------------------------------

def test_detects_url_in_docx_zip_member():
    from app.api.v1.endpoints.canary_token_scan import _scan_zip_bytes

    data = _make_docx_with_url("https://canarytokens.com/traffic/abc123/index.html")
    findings = _scan_zip_bytes(data)
    assert len(findings) == 1
    assert findings[0].url == "https://canarytokens.com/traffic/abc123/index.html"
    assert findings[0].location == "word/_rels/document.xml.rels"


def test_ignores_known_schema_domains():
    from app.api.v1.endpoints.canary_token_scan import _scan_zip_bytes

    data = _make_clean_docx()
    findings = _scan_zip_bytes(data)
    # word/document.xml referenziert selbst schemas.openxmlformats.org im xmlns --
    # das MUSS rausgefiltert sein, sonst waere jedes Office-Dokument "verdaechtig".
    assert findings == []


def test_detects_url_in_compressed_pdf_stream():
    from app.api.v1.endpoints.canary_token_scan import _scan_pdf_bytes

    data = _make_pdf_with_compressed_url("https://tracker.honeytoken.example/x/9f8e7d")
    findings = _scan_pdf_bytes(data)
    assert any(f.url == "https://tracker.honeytoken.example/x/9f8e7d" for f in findings)
    assert any("komprimiert" in f.location for f in findings)


def test_detects_url_in_raw_pdf_bytes():
    from app.api.v1.endpoints.canary_token_scan import _scan_pdf_bytes

    data = _make_pdf_with_raw_url("https://example.com/tracker/xyz")
    findings = _scan_pdf_bytes(data)
    assert any(f.url == "https://example.com/tracker/xyz" for f in findings)


def test_url_cleanup_strips_trailing_punctuation():
    from app.api.v1.endpoints.canary_token_scan import _clean_url

    assert _clean_url(b"https://example.com/x).") == "https://example.com/x"
    assert _clean_url(b"https://example.com/x',") == "https://example.com/x"


# --- HTTP-Endpunkt -------------------------------------------------------------

def test_scan_endpoint_flags_suspicious_docx(client):
    import pyotp
    from tests.conftest import create_admin as _create_admin

    password = _create_admin()
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    pending = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending, "code": code})

    data = _make_docx_with_url("https://canarytokens.com/traffic/abc123/index.html")
    r = client.post(
        "/api/v1/canary-token-scan",
        files={"file": ("verdaechtig.docx", data, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["suspicious"] is True
    assert body["file_type"] == "office/zip"
    assert len(body["findings"]) == 1


def test_scan_endpoint_clean_docx_not_suspicious(client):
    import pyotp
    from tests.conftest import create_admin as _create_admin

    password = _create_admin()
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    pending = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending, "code": code})

    data = _make_clean_docx()
    r = client.post("/api/v1/canary-token-scan", files={"file": ("sauber.docx", data, "application/octet-stream")})
    assert r.status_code == 200
    assert r.json()["suspicious"] is False


def test_scan_endpoint_detects_type_by_content_not_extension(client):
    """Eine .docx-Datei, die eigentlich ein PDF ist (falsch benannt) --
    die Magic-Bytes-Erkennung muss trotzdem den echten Typ erkennen."""
    import pyotp
    from tests.conftest import create_admin as _create_admin

    password = _create_admin()
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    pending = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending, "code": code})

    data = _make_pdf_with_raw_url("https://example.com/tracker")
    r = client.post("/api/v1/canary-token-scan", files={"file": ("umbenannt.docx", data, "application/octet-stream")})
    assert r.status_code == 200
    assert r.json()["file_type"] == "pdf"
    assert r.json()["suspicious"] is True


def test_scan_endpoint_rejects_unsupported_format(client):
    import pyotp
    from tests.conftest import create_admin as _create_admin

    password = _create_admin()
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    pending = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending, "code": code})

    r = client.post("/api/v1/canary-token-scan", files={"file": ("random.txt", b"nur normaler text, kein pdf oder zip", "text/plain")})
    assert r.status_code == 422


def test_scan_endpoint_rejects_empty_file(client):
    import pyotp
    from tests.conftest import create_admin as _create_admin

    password = _create_admin()
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    pending = r.json()["pending_token"]
    r = client.post("/api/v1/auth/2fa/totp/setup/start", json={"pending_token": pending})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/2fa/totp/setup/verify", json={"pending_token": pending, "code": code})

    r = client.post("/api/v1/canary-token-scan", files={"file": ("empty.pdf", b"", "application/pdf")})
    assert r.status_code == 422


def test_scan_endpoint_requires_auth(client):
    r = client.post("/api/v1/canary-token-scan", files={"file": ("x.pdf", b"%PDF-1.4\n%%EOF", "application/pdf")})
    assert r.status_code == 401
