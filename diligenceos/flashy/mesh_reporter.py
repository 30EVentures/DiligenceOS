"""FlashyOS mesh reporter (presence only), stdlib only. Same rules as reporter.js.

Sends nothing unless ALL of FLASHYOS_ORG_ID, FLASHYOS_AGENT_TOKEN and FLASHYOS_AGENT_NAME are set.
Wire format taken from @flashyos/agent 0.21.0:
    POST {base}/api/v1/agents/heartbeat   {orgId, token, agentName, status, currentTask, progress}
The token is read from the environment only and never appears in any return value, error or log line.
The base URL must be https (http only for 127.0.0.1, used by tests). Failures never raise and never retry.
The task label is a short fixed string chosen by the caller, never document contents or user text.
Run this file directly for a DRY RUN; add --send to send one IDLE heartbeat (and --every N to repeat).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

STATUSES = ("PLANNING", "PRESENTING", "BUILDING", "ACTIVE", "TESTING", "DEPLOYING", "REVIEWING", "INCIDENT", "IDLE")
DEFAULT_BASE = "https://api.flashyos.com"
_ORG = re.compile(r"^[A-Za-z0-9_-]{3,64}\Z")
_NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*\Z")
_TOKEN = re.compile(r"^[\x21-\x7e]{8,512}\Z")


def read_config(env=None):
    env = os.environ if env is None else env
    org, token, name = env.get("FLASHYOS_ORG_ID", ""), env.get("FLASHYOS_AGENT_TOKEN", ""), env.get("FLASHYOS_AGENT_NAME", "")
    base = env.get("FLASHYOS_API_URL", DEFAULT_BASE)
    if not (org and token and name):
        return {"configured": False, "reason": "NOT_CONFIGURED"}
    if not _ORG.match(org):
        return {"configured": False, "reason": "BAD_ORG_ID"}
    if not _NAME.match(name) or len(name) > 64:
        return {"configured": False, "reason": "BAD_AGENT_NAME"}
    if not _TOKEN.match(token):
        return {"configured": False, "reason": "BAD_TOKEN_SHAPE"}
    try:
        u = urllib.parse.urlsplit(base)
        host = u.hostname
        _ = u.port
    except ValueError:
        return {"configured": False, "reason": "BAD_API_URL"}
    local = u.scheme == "http" and host == "127.0.0.1"
    if u.scheme != "https" and not local:
        return {"configured": False, "reason": "API_URL_NOT_HTTPS" if u.scheme in ("http", "https") else "BAD_API_URL"}
    if not host or u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
        return {"configured": False, "reason": "BAD_API_URL"}
    return {"configured": True, "orgId": org, "token": token, "agentName": name, "baseUrl": f"{u.scheme}://{u.netloc}"}


def _clean_task(t) -> str:
    return re.sub(r"[^\x20-\x7e]", " ", str(t if t is not None else "")).strip()[:120]


def describe_heartbeat(cfg, status, task="", progress=0):
    """The request that WOULD be sent, token redacted. Safe to print."""
    return {"url": cfg["baseUrl"] + "/api/v1/agents/heartbeat",
            "body": {"orgId": cfg["orgId"], "token": "[redacted]", "agentName": cfg["agentName"], "status": status,
                     "currentTask": _clean_task(task), "progress": progress}}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def heartbeat(status, task="", progress=0, env=None, timeout=5.0, opener=None):
    """Returns {'sent': bool, 'reason'?: str, 'httpStatus'?: int}. Never raises."""
    cfg = read_config(env)
    if not cfg["configured"]:
        return {"sent": False, "reason": cfg["reason"]}
    if status not in STATUSES:
        return {"sent": False, "reason": "BAD_STATUS"}
    if not isinstance(progress, int) or isinstance(progress, bool) or not 0 <= progress <= 100:
        return {"sent": False, "reason": "BAD_PROGRESS"}
    body = json.dumps({"orgId": cfg["orgId"], "token": cfg["token"], "agentName": cfg["agentName"], "status": status,
                       "currentTask": _clean_task(task), "progress": progress}).encode()
    req = urllib.request.Request(cfg["baseUrl"] + "/api/v1/agents/heartbeat", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        op = opener or urllib.request.build_opener(_NoRedirect)
        with op.open(req, timeout=timeout) as r:
            return {"sent": 200 <= r.status < 300, "httpStatus": r.status}
    except urllib.error.HTTPError as e:
        return {"sent": False, "reason": f"HTTP_{e.code}", "httpStatus": e.code}
    except Exception:  # noqa: BLE001 - presence must never break the product
        return {"sent": False, "reason": "NETWORK_ERROR"}


def idle(**kw):
    return heartbeat("IDLE", "", 0, **kw)


def main(argv):
    send = "--send" in argv
    every = 0
    if "--every" in argv:
        try:
            every = int(argv[argv.index("--every") + 1])
        except (ValueError, IndexError):
            every = -1
        if not 10 <= every <= 3600:
            print("--every takes whole seconds from 10 to 3600", file=sys.stderr)
            return 2
    cfg = read_config()
    if not cfg["configured"]:
        print(f"not configured ({cfg['reason']}). Set FLASHYOS_ORG_ID, FLASHYOS_AGENT_TOKEN, FLASHYOS_AGENT_NAME.", file=sys.stderr)
        return 2
    print(json.dumps(describe_heartbeat(cfg, "IDLE"), indent=2))
    if not send:
        print("\ndry run: nothing sent. Add --send to send.")
        return 0

    def once():
        out = idle()
        print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} heartbeat: {'sent' if out['sent'] else 'NOT sent'}"
              + (f" ({out['reason']})" if out.get("reason") else ""), flush=True)
        return out

    first = once()
    if not every:
        return 0 if first["sent"] else 1
    try:
        while True:
            time.sleep(every)
            once()
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
