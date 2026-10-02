from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[3]
ADAPTER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location(
    "frequency_aya_workcell_adapter", ADAPTER_DIR / "adapter.py"
)
assert spec is not None and spec.loader is not None
aya_adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aya_adapter)

AyaProfileError = aya_adapter.AyaProfileError
build_conformance_run = aya_adapter.build_conformance_run
candidate_effect_digest = aya_adapter.candidate_effect_digest
lease_digest = aya_adapter.lease_digest
score_digest = aya_adapter.score_digest
validate_profile = aya_adapter.validate_profile

from conformance import closure_payload, digest, evaluate_run, observation_payload

PROFILE = ADAPTER_DIR / "fixtures" / "profile.json"


def _profile():
    return json.loads(PROFILE.read_text(encoding="utf-8"))


def _score():
    return {
        "schema": "aya.score/v0",
        "scoreId": "demo-score",
        "origin": {"author": "human://demo", "gesture": "Create a derived scene"},
        "intent": "Create a derived candidate without overwriting source",
        "inputs": [{"path": "input/scene.blend", "sha256": "a" * 64}],
        "invariants": ["source remains unchanged"],
        "variationSpace": ["lighting may change"],
        "evidenceRequired": ["after_image", "artifact_hash"],
        "budget": {"wallTimeSeconds": 300, "maxAttempts": 3},
        "isolationRequired": "contract_only",
    }


def _lease(score):
    return {
        "schema": "aya.lease/v0",
        "leaseId": "lease-demo",
        "scoreSha256": score_digest(score),
        "workerId": "aya-worker-demo",
        "createdAt": "2026-10-02T18:00:00Z",
        "expiresAt": "2026-10-02T18:10:00Z",
        "isolationRequired": "contract_only",
        "network": "deny",
        "allowRawCode": True,
        "mounts": {
            "input": "input",
            "work": "work",
            "output": "output",
        },
    }


def _capability_report(lease):
    return {
        "schema": "aya.capability-report/v0",
        "runtimeId": lease["workerId"],
        "generatedAt": "2026-10-02T18:00:30Z",
        "isolationLevel": "contract_only",
        "sourceReadOnly": True,
        "outputIsolated": True,
        "processTreeReaped": True,
        "networkModes": ["deny"],
        "claims": ["synthetic research runtime"],
    }


def _receipt(score, lease):
    candidate = {
        "sources": [{
            "path": "input/scene.blend",
            "beforeSha256": "a" * 64,
            "afterSha256": "a" * 64,
        }],
        "artifacts": [{"path": "output/candidate.blend", "sha256": "b" * 64}],
        "evidence": [
            {"kind": "after_image", "path": "output/after.png", "sha256": "c" * 64},
            {"kind": "artifact_hash", "path": "output/hash.txt", "sha256": "d" * 64},
        ],
    }
    return {
        "schema": "aya.receipt/v0",
        "receiptId": "receipt-demo",
        "scoreSha256": score_digest(score),
        "leaseSha256": lease_digest(lease),
        "status": "candidate_ready",
        "events": [{
            "index": 0,
            "at": "2026-10-02T18:05:00Z",
            "kind": "candidate",
            "summary": "candidate produced",
            "previousSha256": "0" * 64,
            "eventSha256": "e" * 64,
        }],
        "candidate": candidate,
        "sealedAt": "2026-10-02T18:06:00Z",
        "receiptSha256": "f" * 64,
    }


def _keys():
    observer_private = Ed25519PrivateKey.generate()
    closure_private = Ed25519PrivateKey.generate()
    observer_public = observer_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    closure_public = closure_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return observer_private, observer_public, closure_private, closure_public


def _attest(private, payload_digest):
    signature = private.sign(payload_digest.encode("ascii"))
    return {
        "payload_digest": payload_digest,
        "signature": base64.b64encode(signature).decode("ascii"),
        "algorithm": "Ed25519",
    }


def _run():
    score = _score()
    lease = _lease(score)
    capability_report = _capability_report(lease)
    receipt = _receipt(score, lease)
    effect = candidate_effect_digest(receipt)
    run = build_conformance_run(
        profile=_profile(),
        score=score,
        lease=lease,
        capability_report=capability_report,
        receipt=receipt,
        principal="human://demo",
        target="aya://workcell/demo-score/candidate",
        observer_id="observer://independent/aya-demo",
        observed_at=1727892390,
        observation_effect_digest=effect,
        receipt_anchor_ref="sha256:" + receipt["receiptSha256"],
        observation_receipt_ref="sha256:" + "1" * 64,
    )
    return run, score, lease, receipt


def _seal(run, observer_private, closure_private):
    run["evidence"]["observer_attestation"] = _attest(
        observer_private, digest(observation_payload(run))
    )
    run["evidence"]["closure"] = _attest(
        closure_private, digest(closure_payload(run))
    )


def _codes(result):
    return {f["code"] for f in result["findings"]}


def test_profile_preserves_aya_frozen_non_production_boundary():
    profile = _profile()
    validate_profile(profile)
    assert profile["runtime_status"] == "research-frozen"
    assert profile["production_execution_enabled"] is False
    assert profile["claim_boundary"]["aya_receipt_is_independent_observation"] is False
    assert profile["claim_boundary"]["os_sandbox_claimed"] is False


def test_score_lease_receipt_bindings_feed_public_conformance():
    run, _, _, _ = _run()
    observer_private, observer_public, closure_private, closure_public = _keys()
    _seal(run, observer_private, closure_private)

    result = evaluate_run(
        run,
        trusted_observer_id="observer://independent/aya-demo",
        trusted_observer_public_key=observer_public,
        trusted_closure_public_key=closure_public,
    )

    assert result["status"] == "VERIFIED"
    assert result["external_effect_verified"] is True
    assert result["findings"] == []


def test_receipt_cannot_substitute_for_independent_observer():
    run, _, _, _ = _run()
    _, _, closure_private, closure_public = _keys()
    payload = digest(closure_payload(run))
    run["evidence"]["closure"] = _attest(closure_private, payload)

    result = evaluate_run(
        run,
        trusted_observer_id="observer://independent/aya-demo",
        trusted_closure_public_key=closure_public,
    )

    assert "MISSING_OBSERVER_ATTESTATION" in _codes(result)
    assert result["external_effect_verified"] is False


def test_lease_must_bind_exact_score():
    score = _score()
    lease = _lease(score)
    receipt = _receipt(score, lease)
    lease["scoreSha256"] = "0" * 64

    with pytest.raises(AyaProfileError):
        build_conformance_run(
            profile=_profile(),
            score=score,
            lease=lease,
            capability_report=_capability_report(lease),
            receipt=receipt,
            principal="human://demo",
            target="aya://candidate/demo",
            observer_id="observer://demo",
            observed_at=1,
            observation_effect_digest="sha256:" + "b" * 64,
            receipt_anchor_ref="sha256:" + "f" * 64,
            observation_receipt_ref="sha256:" + "1" * 64,
        )


def test_receipt_must_bind_exact_lease():
    score = _score()
    lease = _lease(score)
    receipt = _receipt(score, lease)
    receipt["leaseSha256"] = "0" * 64

    with pytest.raises(AyaProfileError):
        build_conformance_run(
            profile=_profile(),
            score=score,
            lease=lease,
            capability_report=_capability_report(lease),
            receipt=receipt,
            principal="human://demo",
            target="aya://candidate/demo",
            observer_id="observer://demo",
            observed_at=1,
            observation_effect_digest="sha256:" + "b" * 64,
            receipt_anchor_ref="sha256:" + "f" * 64,
            observation_receipt_ref="sha256:" + "1" * 64,
        )


def test_receipt_sealed_after_expiry_fails_closed():
    score = _score()
    lease = _lease(score)
    receipt = _receipt(score, lease)
    receipt["sealedAt"] = "2026-10-02T18:11:00Z"

    with pytest.raises(AyaProfileError):
        build_conformance_run(
            profile=_profile(),
            score=score,
            lease=lease,
            capability_report=_capability_report(lease),
            receipt=receipt,
            principal="human://demo",
            target="aya://candidate/demo",
            observer_id="observer://demo",
            observed_at=1,
            observation_effect_digest="sha256:" + "b" * 64,
            receipt_anchor_ref="sha256:" + "f" * 64,
            observation_receipt_ref="sha256:" + "1" * 64,
        )


def test_isolation_requirement_cannot_be_downgraded():
    score = _score()
    score["isolationRequired"] = "os_enforced"
    lease = _lease(score)
    lease["isolationRequired"] = "contract_only"
    receipt = _receipt(score, lease)

    with pytest.raises(AyaProfileError):
        build_conformance_run(
            profile=_profile(),
            score=score,
            lease=lease,
            capability_report=_capability_report(lease),
            receipt=receipt,
            principal="human://demo",
            target="aya://candidate/demo",
            observer_id="observer://demo",
            observed_at=1,
            observation_effect_digest="sha256:" + "b" * 64,
            receipt_anchor_ref="sha256:" + "f" * 64,
            observation_receipt_ref="sha256:" + "1" * 64,
        )


def test_non_candidate_receipt_cannot_be_promoted():
    score = _score()
    lease = _lease(score)
    receipt = _receipt(score, lease)
    receipt["status"] = "failed"
    receipt["candidate"] = None

    with pytest.raises(AyaProfileError):
        candidate_effect_digest(receipt)


def test_observed_candidate_digest_must_match_execution_candidate():
    run, _, _, _ = _run()
    run["observation"]["effect_digest"] = "sha256:" + "9" * 64
    observer_private, observer_public, closure_private, closure_public = _keys()
    _seal(run, observer_private, closure_private)

    result = evaluate_run(
        run,
        trusted_observer_id="observer://independent/aya-demo",
        trusted_observer_public_key=observer_public,
        trusted_closure_public_key=closure_public,
    )

    assert "OBSERVATION_CORRELATION_MISMATCH" in _codes(result)
    assert result["status"] == "NOT VERIFIED"

def test_capability_report_is_bound_but_not_independent_proof():
    score = _score()
    lease = _lease(score)
    capability = _capability_report(lease)
    capability["runtimeId"] = "other-worker"
    receipt = _receipt(score, lease)

    with pytest.raises(AyaProfileError):
        build_conformance_run(
            profile=_profile(),
            score=score,
            lease=lease,
            capability_report=capability,
            receipt=receipt,
            principal="human://demo",
            target="aya://candidate/demo",
            observer_id="observer://demo",
            observed_at=1,
            observation_effect_digest="sha256:" + "b" * 64,
            receipt_anchor_ref="sha256:" + "f" * 64,
            observation_receipt_ref="sha256:" + "1" * 64,
        )


def test_source_mutation_in_candidate_fails_closed():
    score = _score()
    lease = _lease(score)
    receipt = _receipt(score, lease)
    receipt["candidate"]["sources"][0]["afterSha256"] = "9" * 64

    with pytest.raises(AyaProfileError):
        candidate_effect_digest(receipt)


def test_invalid_native_receipt_digest_is_rejected():
    score = _score()
    lease = _lease(score)
    receipt = _receipt(score, lease)
    receipt["receiptSha256"] = "not-a-digest"

    with pytest.raises(AyaProfileError):
        build_conformance_run(
            profile=_profile(),
            score=score,
            lease=lease,
            capability_report=_capability_report(lease),
            receipt=receipt,
            principal="human://demo",
            target="aya://candidate/demo",
            observer_id="observer://demo",
            observed_at=1,
            observation_effect_digest="sha256:" + "b" * 64,
            receipt_anchor_ref="anchor://example",
            observation_receipt_ref="sha256:" + "1" * 64,
        )
