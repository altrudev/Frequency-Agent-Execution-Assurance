from __future__ import annotations

import hashlib
import importlib.metadata
import json
from pathlib import Path
from typing import Any

from agentrust_trace import validate_json, verify_record

SCHEMA = "frequency.external-evidence.v1"


def _load_object(path: str | Path, label: str) -> dict[str, Any]:
    source = Path(path)
    value = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sha256_file(path: str | Path) -> str:
    return _sha256_bytes(Path(path).read_bytes())


def _stable_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def verify_and_project(
    record_path: str | Path,
    trusted_key_path: str | Path,
) -> dict[str, Any]:
    record = _load_object(record_path, "TRACE record")
    trusted_key = _load_object(trusted_key_path, "trusted TRACE key")

    if "trace" in record and "signature" in record:
        raise ValueError("cMCP RuntimeClaim envelopes are not accepted by this adapter")

    validate_json(record)
    verify_record(record, public_key_or_jwk=trusted_key)

    runtime = record.get("runtime") if isinstance(record.get("runtime"), dict) else {}
    policy = record.get("policy") if isinstance(record.get("policy"), dict) else {}
    provenance = (
        record.get("build_provenance")
        if isinstance(record.get("build_provenance"), dict)
        else {}
    )
    transcript = (
        record.get("tool_transcript")
        if isinstance(record.get("tool_transcript"), dict)
        else {}
    )

    projection = {
        "schema": SCHEMA,
        "source": {
            "format": "TRACE",
            "verifier": "agentrust-trace",
            "verifier_version": importlib.metadata.version("agentrust-trace"),
            "record_sha256": _sha256_file(record_path),
            "trusted_key_sha256": _sha256_file(trusted_key_path),
            "trusted_key_source": "caller-supplied",
        },
        "claims": {
            "subject": record.get("subject"),
            "runtime_measurement": runtime.get("measurement"),
            "policy_bundle_hash": policy.get("bundle_hash"),
            "data_class": record.get("data_class"),
            "build_provenance_digest": provenance.get("digest"),
            "tool_transcript_hash": transcript.get("hash"),
        },
        "verification": {
            "status": "VERIFIED",
            "claim_ceiling": "trace-record-cryptographically-verified",
            "external_effect_verified": False,
            "hardware_attestation_independently_verified": False,
            "transparency_inclusion_independently_verified": False,
            "transcript_content_bound": False,
        },
    }
    projection["projection_sha256"] = _stable_hash(projection)
    return projection
