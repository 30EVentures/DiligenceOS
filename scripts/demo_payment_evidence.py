#!/usr/bin/env python3
"""One payment, authorized and made on the demo spine's MOCK chain, turned into a signed evidence record and checked like a stranger would.

    python3 scripts/demo_payment_evidence.py OUT_DIR [--demo ~/FlashyDemo]

Needs node and the demo repo. Nothing leaves this machine: the chain is an in-memory mock, the keys are throwaway, no funds exist.
It writes the documents and prints the exact commands a third party runs.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from diligenceos.flashy.payment_evidence import build_payment_evidence  # noqa: E402
from diligenceos.signing import Signer  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--demo", default=str(Path.home() / "FlashyDemo"))
    args = ap.parse_args()
    out = Path(args.out).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    done = subprocess.run(["node", str(ROOT / "tests" / "flashy" / "payment_flow_dump.mjs"), args.demo, "1"], capture_output=True, text=True)
    if done.returncode != 0:
        print("could not run the demo spine:", done.stderr[-400:], file=sys.stderr)
        return 2
    flow = json.loads(done.stdout)
    chain = {"chainId": flow["chain"]["id"], "blockNumber": flow["chain"]["tip"], "receipt": flow["chain"]["receipt"]}
    pins = {"plane_pub": flow["planePub"], "log_pub": flow["logPub"], "root_pubs": flow["rootPubs"], "approver_pubs": []}
    for name, doc in (("request", flow["request"]), ("authorization", flow["authorization"]), ("plane-log", flow["entries"]), ("pins", pins), ("chain", chain)):
        (out / f"{name}.json").write_text(json.dumps(doc, indent=2) + "\n")
    signer = Signer.load_or_create(out / "issuer.key")
    rpc = lambda m, p: {"eth_chainId": chain["chainId"], "eth_blockNumber": chain["blockNumber"], "eth_getTransactionReceipt": chain["receipt"]}[m]  # noqa: E731
    evidence = build_payment_evidence(flow["request"], flow["authorization"], flow["entries"], pins=pins, rpc=rpc, signer=signer,
                                      issued_at="2026-10-16T12:00:00.000Z")
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    py = f"{sys.executable} -m diligenceos"
    print(f"wrote the documents and evidence.json to {out}\nissuer to pin: {signer.issuer_id}\n")
    print("A stranger who was told that issuer id runs:\n")
    print(f"  {py} verify-evidence {out}/evidence.json --pin {signer.issuer_id}\n")
    print("and, holding the underlying documents and the keys THEY pinned (pins.json), re-derives it:\n")
    print(f"  {py} recheck-evidence {out}/evidence.json --pin {signer.issuer_id} --request {out}/request.json --authorization {out}/authorization.json \\")
    print(f"      --plane-log {out}/plane-log.json --pins {out}/pins.json --chain {out}/chain.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
