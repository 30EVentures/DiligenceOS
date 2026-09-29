"""python3 -m diligenceos [request.json | keygen | delegate | sign-request ...]

No argument: starts the local web front end (blocks; see diligenceos.webapp).
One argument: batch mode, unchanged since Slice 9 — runs the pipeline once
against a request file and prints the verdict as JSON.
"""

from __future__ import annotations

import json
import sys

from diligenceos.loaders import build_ledger, build_registry_lookup
from diligenceos.pipeline import run_diligence
from diligenceos.sanctions import SanctionsList, load_sanctions_list
from diligenceos.serialize import verdict_result_to_dict


def _run_batch(request_path: str) -> int:
    request = json.loads(open(request_path).read())
    subject = request["subject"]

    sanctions_list = (
        load_sanctions_list(request["sanctions_list_path"])
        if request.get("sanctions_list_path")
        else SanctionsList()
    )
    registry_lookup = build_registry_lookup(request.get("registry", {}))
    ledger = build_ledger(request.get("delivery_records", []))

    result = run_diligence(
        name=subject["name"],
        registration_id=subject["registration_id"],
        sanctions_list=sanctions_list,
        registry_lookup=registry_lookup,
        ledger=ledger,
        document_text=request.get("document_text"),
    )
    print(json.dumps(verdict_result_to_dict(result), indent=2))
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 1:
        from diligenceos import webapp

        webapp.serve()
        return 0

    from diligenceos import tools

    if argv[1] in tools.COMMANDS:
        return tools.main(argv[1:])

    if len(argv) == 2:
        return _run_batch(argv[1])

    print("usage: python3 -m diligenceos [request.json]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
