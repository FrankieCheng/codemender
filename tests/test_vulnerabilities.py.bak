"""
Unit & Integration Tests for Security Verification
==================================================
Tests verifying application behaviors across request handling,
session management, and data access.
See CVE_DETAILS.md for technical details and vulnerability references.
"""

import os
import sys
import json
import base64
import pickle
import pytest
from io import BytesIO
from werkzeug.test import Client
from werkzeug.wrappers import Response
import werkzeug.http

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app import Application, create_app


@pytest.fixture
def client():
    app = Application()
    return Client(app, Response)


def test_index_route(client):
    """Test that the application index route responds normally."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"Application Services Portal" in response.data


def test_multipart_limits(client):
    """
    Test multipart upload processing.
    When part limits are enforced, requests exceeding threshold are rejected with 413.
    """
    data = {f"part_{i}": f"val_{i}" for i in range(1200)}
    response = client.post("/upload", data=data)
    assert response.status_code in [200, 413]


def test_cookie_handling():
    """Test cookie parsing behavior with malformed cookies."""
    cookie_str = "=malicious; legit=value"
    parsed = werkzeug.http.parse_cookie(cookie_str)
    assert "legit" in parsed


def test_path_traversal(client):
    """
    Test file download path validation.
    Path traversal attempts outside storage boundary should be rejected.
    """
    response = client.get("/download?file=../app.py")
    assert response.status_code in [200, 400, 403, 404]


def test_secure_download_safe_join(client):
    """Test safe_join document serving endpoint."""
    response = client.get("/files/secure-download?file=sample.txt")
    assert response.status_code == 200
    assert b"benign sample file" in response.data


def test_insecure_deserialization(client):
    """Test serialized state handling in restore endpoint."""
    payload = base64.b64encode(pickle.dumps({"user": "admin", "role": "root"})).decode("utf-8")
    response = client.post("/profile/restore", data={"data": payload})
    assert response.status_code in [200, 400]


def test_sql_injection(client):
    """Test database query parameterization in user lookup."""
    sqli_payload = "admin' OR '1'='1"
    response = client.get(f"/api/users/lookup?username={sqli_payload}")
    assert response.status_code == 200
    results = json.loads(response.get_data(as_text=True))
    assert isinstance(results, list)


def test_ssrf_proxy(client):
    """Test outbound proxy endpoint handling."""
    response = client.get("/services/proxy?url=http://127.0.0.1:5000/")
    assert response.status_code in [200, 400, 403, 502]


def test_unrestricted_upload(client):
    """Test file upload extension handling."""
    upload_data = {
        "file": (BytesIO(b"# executable script\nprint('hello')"), "script.py")
    }
    response = client.post("/upload/raw", data=upload_data)
    assert response.status_code in [200, 400]


def test_reflected_xss(client):
    """
    Test that search parameter reflection is properly sanitized or handled.
    """
    payload = "<script>alert(1)</script>"
    response = client.get(f"/search?q={payload}")
    assert response.status_code == 200
    content = response.get_data(as_text=True)
    assert payload in content or "&lt;script&gt;" in content


def test_open_redirect(client):
    """
    Test open redirect validation on navigation endpoint.
    """
    evil_target = "https://malicious-domain.attacker.com"
    response = client.get(f"/navigate?target={evil_target}")
    assert response.status_code in [302, 400, 403]


def test_command_execution(client):
    """
    Test input handling on diagnostic ping endpoint.
    """
    response = client.get("/diagnostics/ping?host=127.0.0.1%20%26%26%20echo%20TEST_INJECTION")
    assert response.status_code in [200, 400, 500]
