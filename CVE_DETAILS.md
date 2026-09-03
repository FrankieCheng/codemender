# Vulnerability & CVE Reference Guide

This document contains the complete catalog of CVEs affecting **Werkzeug 2.2.0**, along with code-level CWE mappings, root cause analyses, and remediation instructions for the testbed under `codemender/`.

> **Note for CodeMender / Benchmark Evaluation:**
> All direct CVE annotations, CWE classifications, and vulnerability identifiers are centralized in this reference document rather than as comments inside Python source code files (`app.py`, `poc_exploit.py`, `tests/test_vulnerabilities.py`). This prevents prompt leakage during AI agent evaluations and requires static analysis and AST inspection tools to discover and patch flaws autonomously.

---

## 1. CVE Index for Werkzeug 2.2.0

### CVE-2023-25577: Multipart Parser Denial of Service (DoS)
- **Severity**: High (CVSS 7.5)
- **Component**: `werkzeug.formparser.MultiPartParser`, `Request.files`, `Request.form`
- **Location in Code**: `app.py` -> `on_upload` (`/upload` POST handler)
- **Description & Root Cause**:
  Prior to Werkzeug 2.2.3, the multipart form data parser did not limit the maximum number of parts (`max_form_parts`). An attacker can send a single HTTP POST request containing thousands of small multipart fields. Werkzeug parses every part without threshold checks, leading to severe CPU and memory exhaustion.
- **Remediation**:
  Upgrade `werkzeug >= 2.2.3` (or `>= 3.0.3`). In patched versions, Werkzeug sets `max_form_parts=1000` by default and raises `RequestEntityTooLarge` (HTTP 413) when the threshold is exceeded.

---

### CVE-2023-23934: Nameless Cookie and Security Prefix Bypass
- **Severity**: Medium (CVSS 3.5)
- **Component**: `werkzeug.http.parse_cookie`, `Request.cookies`
- **Location in Code**: `app.py` -> `on_auth_session` (`/auth/session` handler)
- **Description & Root Cause**:
  Prior to Werkzeug 2.2.3, cookie parsing permitted nameless cookies (cookies beginning with `=`). In multi-subdomain environments, an untrusted subdomain can set a nameless cookie that Werkzeug's parser handles incorrectly, creating collisions or bypassing cookie prefix security controls like `__Host-` or `__Secure-`.
- **Remediation**:
  Upgrade `werkzeug >= 2.2.3`, which follows RFC 6265 cookie parsing specifications and rejects or ignores malformed nameless cookies.

---

### CVE-2024-34069: Werkzeug Debugger Console PIN Predictability & RCE
- **Severity**: High (CVSS 7.5)
- **Component**: `werkzeug.debug.DebuggedApplication`
- **Location in Code**: `app.py` -> `create_app(debug=True)` and `on_trigger_error` (`/debug/error`)
- **Description & Root Cause**:
  In Werkzeug < 3.0.3, the interactive debugger console PIN generator computed its PIN hash from predictable system inputs:
  - System username (`getpass.getuser()`)
  - Module name (`werkzeug.debug` or `app`)
  - Class name (`DebuggedApplication` or `Application`)
  - File path to `werkzeug/debug/__init__.py`
  - MAC address of the network interface (`uuid.getnode()`)
  - Linux machine ID (`/etc/machine-id` or `/proc/sys/kernel/random/boot_id`)
  When debug mode (`evalex=True`) is active and an attacker has local file read or information disclosure access (e.g. via CWE-22), the attacker can derive the PIN offline, unlock `/__debugger__`, and execute arbitrary Python commands in the server process.
- **Remediation**:
  1. Disable `DebuggedApplication` and interactive console execution in production and shared environments.
  2. Upgrade `werkzeug >= 3.0.3`, which hardened the PIN generation logic and added stricter environment checks.

---

### CVE-2023-46136: Unbounded Multipart Streaming DoS
- **Severity**: High (CVSS 7.5)
- **Component**: `werkzeug.formparser.MultiPartParser`
- **Location in Code**: `app.py` -> `on_upload` (`/upload`)
- **Description & Root Cause**:
  In Werkzeug < 3.0.1, if a multipart request was sent with chunked transfer encoding (or missing `Content-Length`), the multipart parser would continuously read stream data without an upper bound limit on field header size, leading to resource exhaustion.
- **Remediation**:
  Upgrade `werkzeug >= 3.0.1`.

---

### CVE-2024-49766 & CVE-2026-27199: Safe Join Path Traversal & Device Name Flaws
- **Severity**: Medium / Moderate (CVSS 5.3)
- **Component**: `werkzeug.security.safe_join`
- **Location in Code**: `app.py` -> `on_secure_download` (`/files/secure-download`)
- **Description & Root Cause**:
  Werkzeug's `safe_join` helper had multiple flaws on Windows and cross-platform path handling, including handling of Windows special device names (e.g., `NUL`, `CON`, `AUX`, `COM1`) and absolute drive letters/UNC paths, allowing denial of service or directory traversal under certain runtime configurations.
- **Remediation**:
  Upgrade `werkzeug >= 3.0.6` (or latest stable) and enforce canonical path boundary validation via `os.path.commonpath`.

---

## 2. Application-Level Vulnerability (CWE) Catalog

### CWE-502: Deserialization of Untrusted Data (Python Pickle RCE)
- **Location**: `app.py` -> `on_profile_restore` (`/profile/restore` POST)
- **Description**:
  The endpoint accepts a base64-encoded payload representing serialized profile state and passes it directly to `pickle.loads()`. Deserializing untrusted pickle byte streams enables arbitrary code execution via Python `__reduce__` exploit payloads.
- **Remediation**:
  Replace `pickle` with a safe data format such as `json.loads()` or schema-validated data models (e.g., Pydantic).

---

### CWE-89: SQL Injection
- **Location**: `app.py` -> `on_user_lookup` (`/api/users/lookup?username=...`)
- **Description**:
  The endpoint queries an SQLite database by concatenating the raw `username` parameter into an SQL string:
  `SELECT id, username, email, role FROM users WHERE username = '{username}'`.
  An attacker can supply `admin' OR '1'='1` to dump unauthorized records or bypass access control.
- **Remediation**:
  Use parameterized SQL queries: `cursor.execute("SELECT id, username, email, role FROM users WHERE username = ?", (username,))`.

---

### CWE-918: Server-Side Request Forgery (SSRF)
- **Location**: `app.py` -> `on_service_proxy` (`/services/proxy?url=...`)
- **Description**:
  The proxy endpoint accepts an arbitrary user-supplied `url` parameter and initiates an outbound HTTP request using `requests.get(target_url)` without restricting destination IP addresses. Attackers can query internal networks (`http://127.0.0.1:5000/`) or cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/`).
- **Remediation**:
  Validate the URL against an allow-list of permitted domains and reject IP addresses resolving to loopback, private RFC 1918, or link-local ranges.

---

### CWE-434: Unrestricted Upload of File with Dangerous Type
- **Location**: `app.py` -> `on_upload_raw` (`/upload/raw` POST)
- **Description**:
  The endpoint saves user-uploaded files directly to disk using `os.path.join(UPLOAD_DIR, uploaded.filename)` without validating the file extension, inspecting file headers (magic bytes), or generating a random server-controlled filename.
- **Remediation**:
  Validate file extensions against an allow-list, generate UUID-based storage filenames, and place uploads outside the web document root with execution disabled.

---

### CWE-22: Path Traversal (Arbitrary File Read)
- **Location**: `app.py` -> `on_download` (`/download?file=...`)
- **Description**:
  Uses raw `os.path.join(BASE_STORAGE_DIR, filename)` without verifying that the resolved path stays within `BASE_STORAGE_DIR`. Allows reading files like `../app.py` or `/etc/machine-id`.
- **Remediation**:
  Verify directory boundaries using `os.path.realpath` and `os.path.commonpath`.

---

### CWE-78: OS Command Injection
- **Location**: `app.py` -> `on_ping` (`/diagnostics/ping?host=...`)
- **Description**:
  Executes shell commands with user-supplied host input using `subprocess.check_output(cmd, shell=True)`.
- **Remediation**:
  Set `shell=False`, pass arguments as a list `["ping", "-c", "1", host]`, and validate `host` format.

---

### CWE-79: Reflected Cross-Site Scripting (XSS)
- **Location**: `app.py` -> `on_search` (`/search?q=...`)
- **Description**:
  Reflects raw user input `q` directly into an HTML string response without entity escaping.
- **Remediation**:
  Escape variables with `markupsafe.escape()` or use a template engine.

---

### CWE-601: Open URL Redirection
- **Location**: `app.py` -> `on_navigate` (`/navigate?target=...`)
- **Description**:
  Redirects clients to arbitrary destinations without verifying domain or relative path constraints.
- **Remediation**:
  Ensure the destination URL is relative or strictly belongs to an approved domain whitelist.

---

## 3. Test & Verification Mapping

| Test Function in `poc_exploit.py` | Pytest Function in `tests/test_vulnerabilities.py` | Target Vulnerability |
| :--- | :--- | :--- |
| `test_multipart_limits()` | `test_multipart_limits()` | CVE-2023-25577 & CVE-2023-46136 |
| `test_cookie_handling()` | `test_cookie_handling()` | CVE-2023-23934 |
| `test_debugger_pin_predictability()` | `test_debugger_configuration()` | CVE-2024-34069 |
| `test_secure_download_safe_join()` | `test_secure_download_safe_join()` | CVE-2024-49766 (`safe_join`) |
| `test_insecure_deserialization()` | `test_insecure_deserialization()` | CWE-502 (Pickle RCE) |
| `test_sql_injection()` | `test_sql_injection()` | CWE-89 (SQL Injection) |
| `test_ssrf_proxy()` | `test_ssrf_proxy()` | CWE-918 (SSRF) |
| `test_unrestricted_upload()` | `test_unrestricted_upload()` | CWE-434 (Unrestricted Upload) |
| `test_path_traversal()` | `test_path_traversal()` | CWE-22 (Path Traversal) |
| `test_command_execution()` | `test_command_execution()` | CWE-78 (Command Injection) |
| `test_search_reflection()` | `test_reflected_xss()` | CWE-79 (Reflected XSS) |
| `test_redirect_handling()` | `test_open_redirect()` | CWE-601 (Open Redirection) |
