from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

import agentrust_trace

from adapter import verify_and_project


def base_record() -> dict:
    return {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": int(time.time()),
        "subject": "spiffe://example.test/agent/generated-artifact",
        "model": {"provider": "example", "model_id": "demo"},
        "runtime": {
            "platform": "software-only",
            "measurement": "sha256:" + "0" * 64,
        },
        "policy": {
            "bundle_hash": "sha256:" + "b" * 64,
            "enforcement_mode": "enforce",
        },
        "data_class": "internal",
        "build_provenance": {
            "slsa_level": 1,
            "digest": "sha256:" + "e" * 64,
        },
        "appraisal": {
            "status": "none",
            "verifier": "https://verifier.example.test",
        },
        "transparency": "https://registry.example.test/trace/sample",
    }


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        key = agentrust_trace.generate_key()
        signed = agentrust_trace.sign_record(base_record(), key)
        record_path = root / "record.json"
        key_path = root / "issuer.jwk"
        record_path.write_text(json.dumps(signed), encoding="utf-8")
        key_path.write_text(
            json.dumps(agentrust_trace.key_to_jwk(key)), encoding="utf-8"
        )
        print(json.dumps(verify_and_project(record_path, key_path), indent=2))


if __name__ == "__main__":
    main()
