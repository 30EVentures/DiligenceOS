"""A small, dependency-free web front end for DiligenceOS (stdlib WSGI only).

Runs against a Store seeded from the bundled Phase 0 sample dataset,
editable at /data — additions are checkable immediately and, since
Slice 13, persisted to DILIGENCEOS_DATA_PATH (default
~/.diligenceos/store.json), outside this repo. See docs/decisions.md.
"""

from __future__ import annotations

import html
import os
import sys
from pathlib import Path
from urllib.parse import parse_qsl
from wsgiref.simple_server import make_server

from diligenceos import api
from diligenceos.pipeline import run_diligence
from diligenceos.store import Store
from diligenceos.types import CheckStatus, Verdict, VerdictResult

DEFAULT_DATA_PATH = "~/.diligenceos/store.json"

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
          max-width: 680px; margin: 0 auto; padding: 48px 24px 96px; }}
  h1 {{ font-size: 28px; margin: 0 0 4px; }}
  h2 {{ font-size: 17px; margin: 32px 0 8px; }}
  p.sub {{ color: #5C5648; margin: 0 0 16px; font-size: 14px; }}
  nav {{ margin: 0 0 28px; font-size: 14px; }}
  nav a {{ color: #1F3B4D; margin-right: 16px; }}
  label {{ display: block; font-weight: 600; margin: 14px 0 4px; font-size: 13px; }}
  input, textarea, select {{ width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 14px;
                      border: 1px solid #DDD6C4; border-radius: 6px; font-family: inherit; }}
  textarea {{ height: 100px; }}
  button {{ margin-top: 16px; padding: 9px 18px; font-size: 14px; font-weight: 600;
            background: #171B1F; color: #fff; border: none; border-radius: 6px; cursor: pointer; }}
  .badge {{ display: inline-block; padding: 6px 14px; border-radius: 8px; font-weight: 600;
            font-size: 13px; letter-spacing: 0.04em; }}
  .finding {{ padding: 10px 12px; border: 1px solid #E7E1D2; border-radius: 8px; margin-top: 8px;
              font-size: 13px; }}
  .finding.flag {{ border-color: #C9C1AB; background: #FBFAF6; }}
  a.back {{ display: inline-block; margin-top: 24px; font-size: 14px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 4px; }}
  th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #E7E1D2; }}
  th {{ color: #5C5648; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }}
  fieldset {{ border: 1px solid #E7E1D2; border-radius: 8px; padding: 12px 16px 16px; margin: 12px 0 0; }}
  legend {{ font-size: 13px; font-weight: 600; padding: 0 4px; }}
  .error {{ color: #7A2A20; }}
</style>
</head>
<body>
<h1>DiligenceOS</h1>
<nav><a href="/">Run a check</a><a href="/data">Manage data</a></nav>
<p class="sub">{subtitle}</p>
{body}
</body>
</html>"""

_DEMO_NOTE = "Checked against the store's current data — additions on /data take effect immediately."


def _form_body(error: str | None = None) -> str:
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
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
        f"{findings_html}"
        f'<a class="back" href="/">&larr; Check another</a>'
    )


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{h}</th>" for h in headers)
    if rows:
        body_rows = "".join(
            "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows
        )
    else:
        body_rows = f'<tr><td colspan="{len(headers)}" style="color:#8F8A78">none yet</td></tr>'
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body_rows}</tbody></table>"


def _data_body(store: Store, error: str | None = None) -> str:
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""

    sanctions_table = _table(
        ["Name", "Program", "Aliases"],
        [
            [html.escape(e.name), html.escape(e.program), html.escape(", ".join(e.aliases))]
            for e in store.sanctions_entries
        ],
    )
    registry_table = _table(
        ["Registration ID", "Name", "Status", "Jurisdiction"],
        [
            [html.escape(r.registration_id), html.escape(r.name), html.escape(r.status), html.escape(r.jurisdiction)]
            for r in store.registry_records
        ],
    )
    delivery_table = _table(
        ["Subject", "On time", "Note"],
        [
            [html.escape(d.subject), "yes" if d.on_time else "no", html.escape(d.note)]
            for d in store.delivery_records
        ],
    )

    return f"""{error_html}
<h2>Sanctions list</h2>
{sanctions_table}
<fieldset>
<legend>Add a sanctions entry</legend>
<form method="post" action="/data/sanctions">
  <label for="s_name">Name</label>
  <input id="s_name" name="name" required>
  <label for="s_program">Program</label>
  <input id="s_program" name="program" required>
  <label for="s_aliases">Aliases (comma-separated, optional)</label>
  <input id="s_aliases" name="aliases">
  <button type="submit">Add</button>
</form>
</fieldset>

<h2>Registry</h2>
{registry_table}
<fieldset>
<legend>Add a registry record</legend>
<form method="post" action="/data/registry">
  <label for="r_id">Registration ID</label>
  <input id="r_id" name="registration_id" required>
  <label for="r_name">Name</label>
  <input id="r_name" name="name" required>
  <label for="r_status">Status</label>
  <select id="r_status" name="status">
    <option value="active">active</option>
    <option value="dissolved">dissolved</option>
    <option value="suspended">suspended</option>
  </select>
  <label for="r_jurisdiction">Jurisdiction (optional)</label>
  <input id="r_jurisdiction" name="jurisdiction">
  <button type="submit">Add</button>
</form>
</fieldset>

<h2>Delivery records</h2>
{delivery_table}
<fieldset>
<legend>Add a delivery record</legend>
<form method="post" action="/data/delivery">
  <label for="d_subject">Subject</label>
  <input id="d_subject" name="subject" required>
  <label style="display:flex;align-items:center;gap:8px;font-weight:400">
    <input type="checkbox" name="on_time" value="yes" checked style="width:auto">
    Delivered on time
  </label>
  <label for="d_note">Note (optional)</label>
  <input id="d_note" name="note">
  <button type="submit">Add</button>
</form>
</fieldset>"""


_REASONS = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed", 413: "Payload Too Large",
            503: "Service Unavailable"}

_store: Store | None = None


def _data_path() -> Path:
    return Path(os.environ.get("DILIGENCEOS_DATA_PATH", DEFAULT_DATA_PATH)).expanduser()


def _get_store() -> Store:
    global _store
    if _store is None:
        _store = Store.load_or_seed(_data_path())
    return _store


def _read_form(environ) -> dict:
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    body = environ["wsgi.input"].read(length) if length else b""
    return dict(parse_qsl(body.decode("utf-8")))


def _html_response(start_response, subtitle: str, body: str, status: str = "200 OK"):
    page = _PAGE.format(subtitle=html.escape(subtitle), body=body).encode("utf-8")
    start_response(status, [("Content-Type", "text/html; charset=utf-8")])
    return [page]


def _redirect(start_response, location: str):
    start_response("302 Found", [("Location", location)])
    return [b""]


def app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")
    store = _get_store()

    if path.startswith("/v1/"):
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        # read one byte past the cap so an oversize body is detected, not truncated
        body = environ["wsgi.input"].read(min(length, api.MAX_BODY_BYTES + 1)) if length else b""
        status, headers, payload = api.handle(method, path, body, store)
        start_response(f"{status} {_REASONS.get(status, 'Error')}", headers)
        return [payload]

    if method == "GET" and path == "/":
        return _html_response(
            start_response,
            "One verdict, before any transaction, hire, or contract.",
            _form_body(),
        )

    if method == "GET" and path == "/data":
        return _html_response(start_response, "The data checks run against, editable here.", _data_body(store))

    if method == "POST" and path == "/verdict":
        form = _read_form(environ)
        name = form.get("name", "").strip()
        registration_id = form.get("registration_id", "").strip()
        document_text = form.get("document_text", "").strip() or None

        if not name or not registration_id:
            return _html_response(
                start_response,
                "One verdict, before any transaction, hire, or contract.",
                _form_body(error="Subject name and registration ID are both required."),
                status="400 Bad Request",
            )

        result = run_diligence(
            name=name,
            registration_id=registration_id,
            sanctions_list=store.sanctions_list(),
            registry_lookup=store.registry_lookup(),
            ledger=store.ledger,
            document_text=document_text,
        )
        return _html_response(start_response, _DEMO_NOTE, _result_body(name, registration_id, result))

    if method == "POST" and path == "/data/sanctions":
        form = _read_form(environ)
        name = form.get("name", "").strip()
        program = form.get("program", "").strip()
        if not name or not program:
            return _html_response(
                start_response, "The data checks run against, editable here.",
                _data_body(store, error="Name and program are both required."),
                status="400 Bad Request",
            )
        aliases = [a.strip() for a in form.get("aliases", "").split(",") if a.strip()]
        store.add_sanctions_entry(name=name, program=program, aliases=aliases)
        return _redirect(start_response, "/data")

    if method == "POST" and path == "/data/registry":
        form = _read_form(environ)
        registration_id = form.get("registration_id", "").strip()
        name = form.get("name", "").strip()
        if not registration_id or not name:
            return _html_response(
                start_response, "The data checks run against, editable here.",
                _data_body(store, error="Registration ID and name are both required."),
                status="400 Bad Request",
            )
        store.add_registry_record(
            registration_id=registration_id,
            name=name,
            status=form.get("status", "active").strip() or "active",
            jurisdiction=form.get("jurisdiction", "").strip(),
        )
        return _redirect(start_response, "/data")

    if method == "POST" and path == "/data/delivery":
        form = _read_form(environ)
        subject = form.get("subject", "").strip()
        if not subject:
            return _html_response(
                start_response, "The data checks run against, editable here.",
                _data_body(store, error="Subject is required."),
                status="400 Bad Request",
            )
        store.add_delivery_record(
            subject=subject, on_time="on_time" in form, note=form.get("note", "").strip()
        )
        return _redirect(start_response, "/data")

    start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
    return [b"not found"]


def serve(host: str | None = None, port: int | None = None) -> None:
    host = host or os.environ.get("DILIGENCEOS_HOST", "127.0.0.1")
    port = port or int(os.environ.get("DILIGENCEOS_PORT", "8000"))
    with make_server(host, port, app) as server:
        print(f"DiligenceOS running at http://{host}:{port}", file=sys.stderr)
        server.serve_forever()
