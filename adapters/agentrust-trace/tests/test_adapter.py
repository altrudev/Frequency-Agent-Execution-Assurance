from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import agentrust_trace
import pytest
from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapter import SCHEMA, verify_and_project


def _base_record() -> dict:
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


def _case(tmp_path: Path):
    key = agentrust_trace.generate_key()
    signed = agentrust_trace.sign_record(_base_record(), key)
    record_path = tmp_path / "record.json"
    key_path = tmp_path / "issuer.jwk"
    record_path.write_text(json.dumps(signed), encoding="utf-8")
    key_path.write_text(json.dumps(agentrust_trace.key_to_jwk(key)), encoding="utf-8")
    return signed, record_path, key_path


def test_valid_record_projects_bounded_verified_evidence(tmp_path):
    _, record_path, key_path = _case(tmp_path)
    result = verify_and_project(record_path, key_path)

    assert result["schema"] == SCHEMA
    assert result["verification"]["status"] == "VERIFIED"
    assert result["verification"]["external_effect_verified"] is False
    assert result["verification"]["hardware_attestation_independently_verified"] is False
    assert result["source"]["trusted_key_source"] == "caller-supplied"
    assert result["projection_sha256"].startswith("sha256:")


def test_tampering_fails_closed(tmp_path):
    signed, record_path, key_path = _case(tmp_path)
    signed["subject"] = "spiffe://example.test/agent/tampered"
    record_path.write_text(json.dumps(signed), encoding="utf-8")

    with pytest.raises(InvalidSignature):
        verify_and_project(record_path, key_path)


def test_wrong_trusted_key_fails_closed(tmp_path):
    _, record_path, _ = _case(tmp_path)
    wrong = agentrust_trace.generate_key()
    wrong_path = tmp_path / "wrong.jwk"
    wrong_path.write_text(
        json.dumps(agentrust_trace.key_to_jwk(wrong)), encoding="utf-8"
    )

    with pytest.raises((InvalidSignature, ValueError)):
        verify_and_project(record_path, wrong_path)
