from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from .bundle import verify_bundle


def _load_public_key(path: str | Path) -> bytes:
    raw = Path(path).read_bytes()
    if len(raw) == 32:
        return raw

    text = raw.decode("ascii").strip()
    if text.startswith("ed25519:"):
        text = text.split(":", 1)[1]

    try:
        decoded = base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise ValueError(
            f"{path} must contain a raw 32-byte Ed25519 key or base64 text"
        ) from exc

    if len(decoded) != 32:
        raise ValueError(f"{path} does not contain a 32-byte Ed25519 public key")
    return decoded


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a Frequency portable evidence bundle offline."
    )
    parser.add_argument("bundle", help="portable evidence bundle JSON")
    parser.add_argument("--issuer-id", required=True, help="trusted bundle issuer identity")
    parser.add_argument(
        "--bundle-key",
        required=True,
        help="trusted Ed25519 bundle issuer public key",
    )
    parser.add_argument(
        "--observer-id",
        required=True,
        help="trusted observer identity expected by the inner run",
    )
    parser.add_argument(
        "--observer-key",
        required=True,
        help="trusted Ed25519 observer public key",
    )
    parser.add_argument(
        "--closure-key",
        required=True,
        help="trusted Ed25519 closing public key",
    )
    parser.add_argument(
        "--expected-nonce",
        help="caller challenge/nonce expected in this bundle",
    )
    parser.add_argument(
        "--expected-adapter",
        help="adapter ID expected by the caller",
    )
    parser.add_argument(
        "--expected-source-commit",
        help="exact source commit expected by the caller",
    )
    parser.add_argument(
        "--seen-bundle-id",
        action="append",
        default=[],
        help="bundle ID already seen by the caller; may be repeated",
    )
    args = parser.parse_args()

    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    if not isinstance(bundle, dict):
        raise ValueError("bundle JSON must be an object")

    result = verify_bundle(
        bundle,
        trusted_issuer_id=args.issuer_id,
        trusted_bundle_public_key=_load_public_key(args.bundle_key),
        trusted_observer_id=args.observer_id,
        trusted_observer_public_key=_load_public_key(args.observer_key),
        trusted_closure_public_key=_load_public_key(args.closure_key),
        expected_nonce=args.expected_nonce,
        expected_adapter_id=args.expected_adapter,
        expected_source_commit=args.expected_source_commit,
        seen_bundle_ids=set(args.seen_bundle_id),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
