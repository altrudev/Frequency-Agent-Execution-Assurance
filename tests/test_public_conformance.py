from __future__ import annotations

import base64
from copy import deepcopy

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conformance import (
    closure_payload,
    digest,
    evaluate_run,
    observation_payload,
)


def _keypair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private, public


def _base_run() -> dict:
    request = {
        "artifact": "sha256:" + "a" * 64,
        "destination": "world://demo/scene-7",
        "mode": "publish",
    }
    return {
        "intent": {
            "principal": "agent://demo-builder",
            "target": "world://demo/scene-7",
            "operation": "publish-artifact",
        },
        "authority": {
            "principal": "agent://demo-builder",
            "target": "world://demo/scene-7",
            "operation": "publish-artifact",
            "request_digest": digest(request),
            "valid_from": 100,
            "valid_until": 200,
        },
        "execution": {
            "principal": "agent://demo-builder",
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


def _seal(
    run: dict,
    observer_private: Ed25519PrivateKey,
    closure_private: Ed25519PrivateKey,
) -> None:
    observation_digest = digest(observation_payload(run))
    observer_signature = observer_private.sign(observation_digest.encode("ascii"))
    run["evidence"]["observer_attestation"] = {
        "payload_digest": observation_digest,
        "signature": base64.b64encode(observer_signature).decode("ascii"),
        "algorithm": "Ed25519",
    }

    payload_digest = digest(closure_payload(run))
    closure_signature = closure_private.sign(payload_digest.encode("ascii"))
    run["evidence"]["closure"] = {
        "payload_digest": payload_digest,
        "signature": base64.b64encode(closure_signature).decode("ascii"),
        "algorithm": "Ed25519",
    }


def _keys():
    observer_private, observer_public = _keypair()
    closure_private, closure_public = _keypair()
    return observer_private, observer_public, closure_private, closure_public


def _evaluate(run: dict, observer_public: bytes, closure_public: bytes) -> dict:
    return evaluate_run(
        run,
        trusted_observer_id="observer://independent/demo",
        trusted_observer_public_key=observer_public,
        trusted_closure_public_key=closure_public,
    )


def _codes(result: dict) -> set[str]:
    return {item["code"] for item in result["findings"]}
def test_valid_run_reaches_external_effect_ceiling():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _base_run()
    _seal(run, observer_private, closure_private)

    result = _evaluate(run, observer_public, closure_public)

    assert result["status"] == "VERIFIED"
    assert result["external_effect_verified"] is True
    assert result["observer_signature_verified"] is True
    assert result["signed_closure_verified"] is True
    assert result["findings"] == []


def test_request_mutation_after_authorization_fails_closed():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _base_run()
    _seal(run, observer_private, closure_private)
    run["execution"]["request"]["mode"] = "replace"

    result = _evaluate(run, observer_public, closure_public)

    assert result["status"] == "NOT VERIFIED"
    assert "AUTHORIZED_REQUEST_MUTATED" in _codes(result)
    assert "CLOSURE_DIGEST_MISMATCH" in _codes(result)
    assert "CLAIM_EXCEEDS_EVIDENCE" in _codes(result)


def test_stale_authority_fails_closed():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _base_run()
    run["execution"]["started_at"] = 201
    _seal(run, observer_private, closure_private)

    result = _evaluate(run, observer_public, closure_public)

    assert "STALE_OR_PREMATURE_AUTHORITY" in _codes(result)
    assert result["external_effect_verified"] is False


def test_self_observation_cannot_satisfy_independence():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _base_run()
    run["observation"]["observer_id"] = run["execution"]["principal"]
    _seal(run, observer_private, closure_private)

    result = _evaluate(run, observer_public, closure_public)

    assert "SELF_OBSERVATION" in _codes(result)
    assert result["external_effect_verified"] is False


def test_unsigned_observation_cannot_be_promoted():
    _, observer_public, closure_private, closure_public = _keys()
    run = _base_run()
    payload_digest = digest(closure_payload(run))
    signature = closure_private.sign(payload_digest.encode("ascii"))
    run["evidence"]["closure"] = {
        "payload_digest": payload_digest,
        "signature": base64.b64encode(signature).decode("ascii"),
        "algorithm": "Ed25519",
    }

    result = _evaluate(run, observer_public, closure_public)

    assert "MISSING_OBSERVER_ATTESTATION" in _codes(result)
    assert result["external_effect_verified"] is False
def test_missing_required_evidence_fails_closed():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _base_run()
    del run["evidence"]["refs"]["observation_receipt"]
    _seal(run, observer_private, closure_private)

    result = _evaluate(run, observer_public, closure_public)

    assert "MISSING_REQUIRED_EVIDENCE" in _codes(result)
    assert result["external_effect_verified"] is False


def test_rewritten_chain_with_recomputed_digest_needs_trusted_signers():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _base_run()
    _seal(run, observer_private, closure_private)

    tampered = deepcopy(run)
    tampered["observation"]["effect_digest"] = "sha256:" + "f" * 64
    tampered["evidence"]["observer_attestation"]["payload_digest"] = digest(
        observation_payload(tampered)
    )
    tampered["evidence"]["closure"]["payload_digest"] = digest(closure_payload(tampered))

    result = _evaluate(tampered, observer_public, closure_public)

    assert "OBSERVER_SIGNATURE_NOT_VERIFIED" in _codes(result)
    assert "CLOSURE_SIGNATURE_NOT_VERIFIED" in _codes(result)
    assert "OBSERVATION_CORRELATION_MISMATCH" in _codes(result)
    assert result["external_effect_verified"] is False


def test_claim_ceiling_prevents_promotion_without_trusted_keys():
    observer_private, _, closure_private, _ = _keys()
    run = _base_run()
    _seal(run, observer_private, closure_private)

    result = evaluate_run(run)

    assert result["status"] == "NOT VERIFIED"
    assert "OBSERVER_SIGNATURE_NOT_VERIFIED" in _codes(result)
    assert "CLOSURE_SIGNATURE_NOT_VERIFIED" in _codes(result)
    assert "CLAIM_EXCEEDS_EVIDENCE" in _codes(result)


def test_observed_effect_digest_must_correlate():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _base_run()
    run["observation"]["effect_digest"] = "sha256:" + "9" * 64
    _seal(run, observer_private, closure_private)

    result = _evaluate(run, observer_public, closure_public)

    assert "OBSERVATION_CORRELATION_MISMATCH" in _codes(result)
    assert result["external_effect_verified"] is False


def test_intent_binding_mismatch_blocks_verification():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _base_run()
    run["intent"]["target"] = "world://demo/other"
    _seal(run, observer_private, closure_private)

    result = _evaluate(run, observer_public, closure_public)

    assert "INTENT_TARGET_MISMATCH" in _codes(result)
    assert result["external_effect_verified"] is False

def test_observer_identity_must_match_trusted_identity():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _base_run()
    run["observation"]["observer_id"] = "observer://spoofed"
    _seal(run, observer_private, closure_private)

    result = _evaluate(run, observer_public, closure_public)

    assert "OBSERVER_ID_NOT_TRUSTED" in _codes(result)
    assert result["external_effect_verified"] is False


def test_required_evidence_set_is_bound_by_closing_signature():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _base_run()
    _seal(run, observer_private, closure_private)
    run["evidence"]["required_refs"] = ["execution_receipt"]

    result = _evaluate(run, observer_public, closure_public)

    assert "CLOSURE_DIGEST_MISMATCH" in _codes(result)
    assert result["external_effect_verified"] is False


def test_signed_closure_binds_intent_object():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _base_run()
    _seal(run, observer_private, closure_private)
    run["intent"]["human_rationale"] = "rewritten after closure"

    result = _evaluate(run, observer_public, closure_public)

    assert "CLOSURE_DIGEST_MISMATCH" in _codes(result)
    assert result["external_effect_verified"] is False


def test_observation_cannot_precede_execution():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _base_run()
    run["observation"]["observed_at"] = run["execution"]["started_at"] - 1
    _seal(run, observer_private, closure_private)

    result = _evaluate(run, observer_public, closure_public)

    assert "OBSERVATION_PRECEDES_EXECUTION" in _codes(result)
    assert result["external_effect_verified"] is False


def test_observation_time_must_be_integer():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _base_run()
    run["observation"]["observed_at"] = "155"
    _seal(run, observer_private, closure_private)

    result = _evaluate(run, observer_public, closure_public)

    assert "INVALID_OBSERVATION_TIME" in _codes(result)
    assert result["external_effect_verified"] is False
