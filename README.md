# Werkzeug 2.2.0 Vulnerability Benchmark for CodeMender

This directory contains a standalone WSGI web application built with **Werkzeug 2.2.0**, intentionally curated with known **CVEs** and code-level **CWEs** to test the identification, verification, and automated patch remediation capabilities of **CodeMender**.

---

## 1. Vulnerability & CVE Catalog

### CVEs in Werkzeug 2.2.0 Dependency

| CVE ID | Severity | Affected Component | Description & Impact | Remediation Target |
| :--- | :--- | :--- | :--- | :--- |
| **CVE-2023-25577** | **High** (CVSS 7.5) | `werkzeug.formparser.MultiPartParser` / `request.files` | **Multipart Parser Resource Exhaustion (DoS):** Prior to Werkzeug 2.2.3, the multipart form data parser did not enforce a limit on the number of parts (`max_form_parts`). An attacker can send thousands of small form parts in a single request, exhausting CPU and memory to cause Denial of Service. | Upgrade `werkzeug >= 2.2.3` (or `>= 3.0.3`) which limits `max_form_parts=1000` and raises `RequestEntityTooLarge`. |
| **CVE-2023-23934** | **Medium** (CVSS 3.5) | `werkzeug.http.parse_cookie` / `request.cookies` | **Nameless Cookie & Prefix Bypass:** Prior to Werkzeug 2.2.3, cookie parsing permitted nameless cookies (`=value`), allowing attackers on adjacent subdomains to overwrite or bypass cookie prefix security controls like `__Host-` or `__Secure-`. | Upgrade `werkzeug >= 2.2.3` and enforce cookie prefix parsing validation. |
| **CVE-2024-34069** | **High** (CVSS 7.5) | `werkzeug.debug.DebuggedApplication` | **Debugger Console PIN Predictability & RCE:** In Werkzeug < 3.0.3, the PIN generator algorithm for the interactive debugger relied on predictable system seeds (MAC address, machine ID, username, module paths). When debug mode or `DebuggedApplication(app, evalex=True)` is enabled, attackers can calculate the PIN and gain arbitrary code execution via `/console`. | Disable `DebuggedApplication` in untrusted/production environments and upgrade `werkzeug >= 3.0.3`. |

---

### Code-Level Vulnerabilities (CWEs)

| CWE ID | Vulnerability Type | Location | Description |
| :--- | :--- | :--- | :--- |
| **CWE-22** | Path Traversal / LFI | `app.py` -> `on_download` (`/download?file=...`) | Reads files from disk without enforcing storage directory boundaries (`../../app.py`, `/etc/machine-id`). Can be chained with **CVE-2024-34069** to leak the machine ID and compute the debugger PIN. |
| **CWE-78** | OS Command Injection | `app.py` -> `on_ping` (`/diagnostics/ping?host=...`) | Passes unvalidated user input directly to a shell (`shell=True`), allowing arbitrary command execution (`127.0.0.1; id`). |
| **CWE-79** | Reflected Cross-Site Scripting (XSS) | `app.py` -> `on_search` (`/search?q=...`) | Reflects unescaped user input in an HTML response. |
| **CWE-601** | Open URL Redirection | `app.py` -> `on_navigate` (`/navigate?target=...`) | Redirects users to arbitrary external URLs without destination validation. |

---

## 2. Directory Structure

```
codemender/
├── README.md               # Benchmark setup and run guide
├── CVE_DETAILS.md          # Full CVE analysis, technical details, and vulnerability catalog
├── requirements.txt        # Pinned dependencies (Werkzeug==2.2.0)
├── app.py                  # Werkzeug 2.2.0 WSGI application
├── poc_exploit.py          # Automated verification script
├── storage/
│   └── sample.txt          # Benign storage asset for path traversal tests
└── tests/
    └── test_vulnerabilities.py  # Pytest verification suite for CodeMender
```

---

## 3. Setup and Execution

### Step 1: Create Virtual Environment & Install Dependencies

```bash
cd codemender
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Run Proof-of-Concept (PoC) Script

Execute the standalone PoC harness to verify the presence of vulnerabilities before remediation:

```bash
python3 poc_exploit.py
```

Expected output:
```text
======================================================================
CodeMender Benchmark: Running Vulnerability Proof-of-Concepts
======================================================================
[VULNERABLE] CVE-2023-25577 Confirmed: Parsed 1500 multipart parts without part limit.
[VULNERABLE] CVE-2023-23934 Confirmed: Nameless cookie key '' is parsed and accepted.
[VULNERABLE] CVE-2024-34069 Confirmed: Generated predictable Werkzeug PIN.
[VULNERABLE] CWE-22 Confirmed: Leaked parent app.py source code via path traversal!
[VULNERABLE] CWE-78 Confirmed: Arbitrary shell command execution succeeded!
[VULNERABLE] CWE-79 Confirmed: Unescaped payload reflected in HTML response!
[VULNERABLE] CWE-601 Confirmed: Open redirect allows arbitrary external domains!
======================================================================
```

### Step 3: Run Automated Tests

```bash
pytest tests/ -v
```

### Step 4: Run the Server (Local Testing Only)

```bash
python3 app.py
```
Open `http://127.0.0.1:5000/` in a local browser to test interactive endpoints.

---

## 4. Evaluation Checklist for CodeMender

When running CodeMender against this repository, it should ideally:
1. **Detect Dependency CVEs**: Flag `Werkzeug==2.2.0` in `requirements.txt` for `CVE-2023-25577`, `CVE-2023-23934`, and `CVE-2024-34069`, proposing an upgrade to a safe version (e.g., `werkzeug>=3.0.3`).
2. **Remediate Debugger Exposure (CVE-2024-34069)**: Remove or guard `DebuggedApplication(app, evalex=True)` so that debug mode and console execution are disabled in non-development configurations.
3. **Remediate Path Traversal (CWE-22)**: Replace raw `os.path.join` with secure path resolution (e.g. `werkzeug.security.safe_join` or resolving realpath and checking directory boundaries).
4. **Remediate Command Injection (CWE-78)**: Replace shell execution with `subprocess.run(["ping", "-c", "1", host], shell=False)` and validate host input.
5. **Remediate XSS (CWE-79)**: Escape user strings with `markupsafe.escape()`.
6. **Remediate Open Redirect (CWE-601)**: Validate that redirection targets are relative paths or within an allow-list of trusted domains.
