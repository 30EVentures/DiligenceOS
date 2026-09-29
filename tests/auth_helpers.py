"""Test helper: sign requests to the authenticated endpoints as the operator."""

from diligenceos.auth import sign_request

AUTHENTICATED_PATHS = ("/v1/revoke", "/v1/spend")


def as_operator(store, path, payload):
    """`payload` with an operator auth envelope, if `path` needs one and it has none."""
    if path in AUTHENTICATED_PATHS and isinstance(payload, dict) and "auth" not in payload:
        return {**payload, "auth": sign_request(store.signer, [], path, payload)}
    return payload
