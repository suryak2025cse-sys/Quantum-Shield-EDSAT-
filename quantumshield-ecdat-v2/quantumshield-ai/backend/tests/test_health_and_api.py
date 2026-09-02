"""
Test Suite: Health Endpoint, Safe Archive Extraction, and API Routing
"""
import io
import zipfile
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import _safe_unpack_zip

client = TestClient(app)


def test_root_and_health_endpoints():
    r1 = client.get("/")
    assert r1.status_code == 200
    assert r1.json()["status"] == "operational"

    r2 = client.get("/health")
    assert r2.status_code == 200
    assert r2.json()["status"] == "ok"
    assert r2.json()["version"] == "0.2.0"

    r3 = client.get("/api/v1/health")
    assert r3.status_code == 200
    assert r3.json()["status"] == "ok"


def test_zip_upload_and_scan():
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("src/auth.py", "import hashlib\ndef h(x): return hashlib.md5(x).hexdigest()\n")
        zf.writestr("requirements.txt", "pycryptodome==3.19.0\n")

    zip_buffer.seek(0)
    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("test_project.zip", zip_buffer, "application/zip")},
        params={"target_name": "api_test_project"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["target_name"] == "api_test_project"
    assert data["total_findings"] >= 1
    assert "normalized_assets" in data
    assert len(data["normalized_assets"]) >= 1


def test_invalid_upload_format():
    response = client.post(
        "/api/v1/scans/upload",
        files={"file": ("malicious.exe", b"MZ...", "application/octet-stream")},
    )
    assert response.status_code == 400


def test_path_traversal_guard(tmp_path):
    # Construct a ZIP containing path traversal entry
    zip_path = tmp_path / "traversal.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../evil.py", "print('owned')")

    extract_dest = tmp_path / "extract"
    extract_dest.mkdir()

    import pytest
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        _safe_unpack_zip(zip_path, extract_dest)
    assert exc_info.value.status_code == 400
    assert "traversal" in exc_info.value.detail.lower()
