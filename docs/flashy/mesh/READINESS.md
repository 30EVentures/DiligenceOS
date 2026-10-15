# DiligenceOS on the FlashyOS mesh: readiness checklist

Prepared 2026-10-14. Nothing here has been run against FlashyOS: no org created, no token minted, no request sent. The dashboard steps are yours. Read `AUDIT.md` first: it lists what is not ready.

## 1. In the dashboard (you)
- Create the organisation (display name `DiligenceOS`, slug `diligenceos`; if the slug is taken pick another and keep the charter slug and env name consistent).
- **Declare no capabilities yet.** A capability claims something is callable. Nothing is deployed and the bundled data is a 3-name sample (`AUDIT.md`, items 6 and 7).
- Mint an agent named `diligenceos-agent`. The token is shown once: put it straight into your shell, never in a file, chat or commit.

## 2. Environment variables
| Variable | Value | Effect |
|---|---|---|
| `FLASHYOS_ORG_ID` | `org_...` from the dashboard | with the next two, turns presence on; without all three nothing is sent |
| `FLASHYOS_AGENT_TOKEN` | the minted token | read from the environment only; never logged or returned |
| `FLASHYOS_AGENT_NAME` | `diligenceos-agent` | must match the minted name |
| `FLASHYOS_API_URL` | (optional) | https only; `http://127.0.0.1` allowed for local tests |
| `DILIGENCEOS_VERDICT_AUTH` | `signed` | **set this before anyone else can reach the server**; the default is `open` |
| `DILIGENCEOS_ADMIN_TOKEN` | any string you choose | enables `/data` writes; unset means they are refused |
| `DILIGENCEOS_HOST` / `PORT` | default `127.0.0.1:8000` | anything but loopback needs a TLS proxy in front |

## 3. Verify, in this order
```bash
# a. nothing is sent without the three variables, and a dry run shows exactly what would be sent
python3 -m diligenceos.flashy.mesh_reporter            # dry run, token redacted
python3 -m diligenceos.flashy.mesh_reporter --send     # one IDLE heartbeat; prints sent / NOT sent (reason)

# b. run the server with presence on, then ask for one verdict
python3 -m diligenceos
curl -s -X POST localhost:8000/v1/verdict -H 'content-type: application/json' \
  -d '{"subject":{"name":"Meridian Robotics Ltd.","registration_id":"UK09456213"}}'

# c. a stranger's check of the charter number, using only the key you pinned
python3 -m diligenceos.flashy.measures --log ~/.diligenceos/receipts.jsonl --pin "$(curl -s localhost:8000/v1/issuer | python3 -c 'import sys,json;print(json.load(sys.stdin)["issuer"])')"
# (for a real check, pin the key out of band, not from the server being checked)

# d. the charter, offline, with the FlashyOS validator
node -e 'const m=require("@flashyos/aao");console.log(m.validateCharterDocument(JSON.parse(require("fs").readFileSync("docs/flashy/mesh/flashyos-charter.draft.json","utf8"))))'   # expect []
```
`NOT sent` reasons: `HTTP_401` wrong token or name, `HTTP_403`/`404` wrong org id, `NETWORK_ERROR`, `API_URL_NOT_HTTPS`.

## 4. What to look for
- Dashboard: the agent appears in a room. It moves to a working room for a moment after a verdict ("Request received", "Gathering evidence", "Verdict issued") and returns to the lounge about 15 s later; a quiet server still sends a heartbeat about every minute.
- The labels are the only text ever sent. No name, document text, verdict or score appears; if you ever see one, stop the server and tell me.
- A verdict request with a misspelt field returns 400 naming the field; with `DILIGENCEOS_VERDICT_AUTH=signed` an unsigned request returns 401.
- `measures` prints `numerator`/`denominator`; `{"ok": false, "code": "LOG_DOES_NOT_VERIFY"}` means the log or the pinned key is wrong, and no number is shown.

## 5. Deliberately not done
No `.well-known/flashyos.json` or charter is served or published (needs a public URL you choose). No capability declared. Nothing contacts FlashyOS or anyone. No deployment.
