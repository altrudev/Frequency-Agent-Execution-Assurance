from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from .evaluator import evaluate_run


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
        description="Evaluate a public Frequency execution-evidence envelope."
    )
    parser.add_argument("run", help="JSON file containing the public run envelope")
    parser.add_argument(
        "--observer-id",
        required=True,
        help="trusted observer identity expected in observation.observer_id",
    )
    parser.add_argument(
        "--observer-key",
        required=True,
        help="trusted Ed25519 observer public key (raw 32 bytes or base64)",
    )
    parser.add_argument(
        "--closure-key",
        required=True,
        help="trusted Ed25519 closing public key (raw 32 bytes or base64)",
    )
    args = parser.parse_args()

    run = json.loads(Path(args.run).read_text(encoding="utf-8"))
    if not isinstance(run, dict):
        raise ValueError("run JSON must be an object")

    result = evaluate_run(
        run,
        trusted_observer_id=args.observer_id,
        trusted_observer_public_key=_load_public_key(args.observer_key),
        trusted_closure_public_key=_load_public_key(args.closure_key),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
