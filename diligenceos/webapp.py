"""A small, dependency-free web front end for DiligenceOS (stdlib WSGI only).

Runs every request against the bundled Phase 0 sample dataset
(fixtures/golden/sample_request.json's registry, sanctions list, and
delivery records) for the life of the process — this is demo data, not a
real registry or sanctions feed. See docs/decisions.md.
"""

from __future__ import annotations

import html
import json
import os
import sys
from pathlib import Path
from urllib.parse import parse_qsl
from wsgiref.simple_server import make_server

from diligenceos.loaders import build_ledger, build_registry_lookup
from diligenceos.pipeline import run_diligence
from diligenceos.sanctions import SanctionsList, load_sanctions_list
from diligenceos.types import CheckStatus, Verdict, VerdictResult

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REQUEST_PATH = REPO_ROOT / "fixtures" / "golden" / "sample_request.json"

_VERDICT_STYLE = {
    Verdict.PROCEED: ("#1E6B45", "#DCEEE1"),
    Verdict.HOLD: ("#7A4A00", "#F3E4C8"),
    Verdict.RED_FLAG: ("#7A2A20", "#F5DCD8"),
}

_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DiligenceOS</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; background: #F7F4ED; color: #171B1F;
          max-width: 640px; margin: 0 auto; padding: 48px 24px; }}
  h1 {{ font-size: 28px; margin: 0 0 4px; }}
  p.sub {{ color: #5C5648; margin: 0 0 32px; font-size: 14px; }}
  label {{ display: block; font-weight: 600; margin: 16px 0 4px; font-size: 14px; }}
  input, textarea {{ width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 14px;
                      border: 1px solid #DDD6C4; border-radius: 6px; font-family: inherit; }}
  textarea {{ height: 100px; }}
  button {{ margin-top: 20px; padding: 10px 20px; font-size: 14px; font-weight: 600;
            background: #171B1F; color: #fff; border: none; border-radius: 6px; cursor: pointer; }}
  .badge {{ display: inline-block; padding: 6px 14px; border-radius: 8px; font-weight: 600;
            font-size: 13px; letter-spacing: 0.04em; }}
  .finding {{ padding: 10px 12px; border: 1px solid #E7E1D2; border-radius: 8px; margin-top: 8px;
              font-size: 13px; }}
  .finding.flag {{ border-color: #C9C1AB; background: #FBFAF6; }}
  a.back {{ display: inline-block; margin-top: 24px; font-size: 14px; }}
</style>
</head>
<body>
<h1>DiligenceOS</h1>
<p class="sub">{subtitle}</p>
{body}
</body>
</html>"""

_DEMO_NOTE = "Checked against the bundled Phase 0 sample dataset — not a real registry or sanctions feed."


def _form_body(error: str | None = None) -> str:
    error_html = f'<p style="color:#7A2A20">{html.escape(error)}</p>' if error else ""
    return f"""{error_html}
<form method="post" action="/verdict">
  <label for="name">Subject name</label>
  <input id="name" name="name" required>
  <label for="registration_id">Registration ID</label>
  <input id="registration_id" name="registration_id" required>
  <label for="document_text">Contract/terms text (optional)</label>
  <textarea id="document_text" name="document_text"></textarea>
  <button type="submit">Check</button>
</form>"""


def _result_body(name: str, registration_id: str, result: VerdictResult) -> str:
    fg, bg = _VERDICT_STYLE[result.verdict]
    findings_html = "".join(
        '<div class="finding{flag_class}"><strong>{category}</strong>: {status}{detail}</div>'.format(
            flag_class=" flag" if f.status is CheckStatus.FLAG else "",
            category=html.escape(f.category),
            status=html.escape(f.status.value),
            detail=f" — {html.escape(f.detail)}" if f.detail else "",
        )
        for f in result.findings
    )
    return (
        f'<p><strong>{html.escape(name)}</strong> ({html.escape(registration_id)})</p>'
        f'<span class="badge" style="color:{fg};background:{bg}">{result.verdict.value}</span>'
        f'<span style="margin-left:12px;color:#5C5648">trust score {result.trust_score}</span>'
        f'{findings_html}'
        f'<a class="back" href="/">&larr; Check another</a>'
    )


def _load_default_context():
    request = json.loads(DEFAULT_REQUEST_PATH.read_text())
    sanctions_list = (
        load_sanctions_list(REPO_ROOT / request["sanctions_list_path"])
        if request.get("sanctions_list_path")
        else SanctionsList()
    )
    registry_lookup = build_registry_lookup(request.get("registry", {}))
    ledger = build_ledger(request.get("delivery_records", []))
    return sanctions_list, registry_lookup, ledger


_context_cache = None


def _context():
    global _context_cache
    if _context_cache is None:
        _context_cache = _load_default_context()
    return _context_cache


def _read_form(environ) -> dict:
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    body = environ["wsgi.input"].read(length) if length else b""
    return dict(parse_qsl(body.decode("utf-8")))


def _html_response(start_response, status: str, subtitle: str, body: str):
    page = _PAGE.format(subtitle=html.escape(subtitle), body=body).encode("utf-8")
    start_response(status, [("Content-Type", "text/html; charset=utf-8")])
    return [page]


def app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")

    if method == "GET" and path == "/":
        return _html_response(
            start_response,
            "200 OK",
            "One verdict, before any transaction, hire, or contract.",
            _form_body(),
        )

    if method == "POST" and path == "/verdict":
        form = _read_form(environ)
        name = form.get("name", "").strip()
        registration_id = form.get("registration_id", "").strip()
        document_text = form.get("document_text", "").strip() or None

        if not name or not registration_id:
            return _html_response(
                start_response,
                "400 Bad Request",
                "One verdict, before any transaction, hire, or contract.",
                _form_body(error="Subject name and registration ID are both required."),
            )

        sanctions_list, registry_lookup, ledger = _context()
        result = run_diligence(
            name=name,
            registration_id=registration_id,
            sanctions_list=sanctions_list,
            registry_lookup=registry_lookup,
            ledger=ledger,
            document_text=document_text,
        )
        return _html_response(
            start_response, "200 OK", _DEMO_NOTE, _result_body(name, registration_id, result)
        )

    start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
    return [b"not found"]


def serve(host: str | None = None, port: int | None = None) -> None:
    host = host or os.environ.get("DILIGENCEOS_HOST", "127.0.0.1")
    port = port or int(os.environ.get("DILIGENCEOS_PORT", "8000"))
    with make_server(host, port, app) as server:
        print(f"DiligenceOS running at http://{host}:{port}", file=sys.stderr)
        server.serve_forever()
