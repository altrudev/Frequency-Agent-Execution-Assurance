from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .evaluator import closure_payload, digest, evaluate_run, observation_payload


def _public_bytes(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _attest(private: Ed25519PrivateKey, payload_digest: str) -> dict[str, str]:
    signature = private.sign(payload_digest.encode("ascii"))
    return {
        "payload_digest": payload_digest,
        "signature": base64.b64encode(signature).decode("ascii"),
        "algorithm": "Ed25519",
    }


def main() -> None:
    observer_key = Ed25519PrivateKey.generate()
    closure_key = Ed25519PrivateKey.generate()

    request = {"artifact": "sha256:" + "a" * 64, "mode": "publish"}
    run = {
        "intent": {
            "principal": "agent://demo",
            "target": "world://demo/scene-7",
            "operation": "publish-artifact",
        },
        "authority": {
            "principal": "agent://demo",
            "target": "world://demo/scene-7",
            "operation": "publish-artifact",
            "request_digest": digest(request),
            "valid_from": 100,
            "valid_until": 200,
        },
        "execution": {
            "principal": "agent://demo",
            "target": "world://demo/scene-7",
            "operation": "publish-artifact",
            "request": request,
            "started_at": 150,
            "effect_digest": "sha256:" + "e" * 64,
        },
        "observation": {
            "observer_id": "observer://independent/demo",
            "independent": True,
            "target": "world://demo/scene-7",
            "operation": "publish-artifact",
            "effect_digest": "sha256:" + "e" * 64,
            "observed_at": 155,
        },
        "evidence": {
            "required_refs": ["execution_receipt", "observation_receipt"],
            "refs": {
                "execution_receipt": "sha256:" + "1" * 64,
                "observation_receipt": "sha256:" + "2" * 64,
            },
        },
        "claims": {"external_effect_verified": True},
    }

    run["evidence"]["observer_attestation"] = _attest(
        observer_key, digest(observation_payload(run))
    )
    run["evidence"]["closure"] = _attest(
        closure_key, digest(closure_payload(run))
    )

    result = evaluate_run(
        run,
        trusted_observer_id="observer://independent/demo",
        trusted_observer_public_key=_public_bytes(observer_key),
        trusted_closure_public_key=_public_bytes(closure_key),
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
