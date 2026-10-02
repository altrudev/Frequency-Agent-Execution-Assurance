from __future__ import annotations

import base64
from copy import deepcopy

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conformance import (
    closure_payload,
    create_bundle,
    digest,
    evaluate_run,
    observation_payload,
    verify_bundle,
)


def _keypair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private, public


def _run():
    request = {
        "artifact": "sha256:" + "a" * 64,
        "destination": "world://portable/demo",
        "mode": "publish",
    }
    return {
        "intent": {
            "principal": "agent://portable-demo",
            "target": "world://portable/demo",
            "operation": "publish-artifact",
        },
        "authority": {
            "principal": "agent://portable-demo",
            "target": "world://portable/demo",
            "operation": "publish-artifact",
            "request_digest": digest(request),
            "valid_from": 100,
            "valid_until": 200,
        },
        "execution": {
            "principal": "agent://portable-demo",
            "target": "world://portable/demo",
            "operation": "publish-artifact",
            "request": request,
            "started_at": 150,
            "effect_digest": "sha256:" + "e" * 64,
        },
        "observation": {
            "observer_id": "observer://portable/demo",
            "independent": True,
            "target": "world://portable/demo",
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


def _seal_run(run, observer_private, closure_private):
    observation_digest = digest(observation_payload(run))
    observer_signature = observer_private.sign(observation_digest.encode("ascii"))
    run["evidence"]["observer_attestation"] = {
        "payload_digest": observation_digest,
        "signature": base64.b64encode(observer_signature).decode("ascii"),
        "algorithm": "Ed25519",
    }

    closing_digest = digest(closure_payload(run))
    closing_signature = closure_private.sign(closing_digest.encode("ascii"))
    run["evidence"]["closure"] = {
        "payload_digest": closing_digest,
        "signature": base64.b64encode(closing_signature).decode("ascii"),
        "algorithm": "Ed25519",
    }


def _case():
    observer_private, observer_public = _keypair()
    closure_private, closure_public = _keypair()
    bundle_private, bundle_public = _keypair()
    run = _run()
    _seal_run(run, observer_private, closure_private)
    bundle = create_bundle(
        run,
        issuer_id="issuer://altru.dev/frequency",
        issued_at=1000,
        nonce="request-123",
        adapter_id="frequency.generated-artifact-world.v1",
        source_commit="7af2d900ffe17be880127fba902f940c7e6d41c8",
        signing_key=bundle_private,
    )
    return bundle, observer_public, closure_public, bundle_public


def _verify(bundle, observer_public, closure_public, bundle_public, **kwargs):
    return verify_bundle(
        bundle,
        trusted_issuer_id="issuer://altru.dev/frequency",
        trusted_bundle_public_key=bundle_public,
        trusted_observer_id="observer://portable/demo",
        trusted_observer_public_key=observer_public,
        trusted_closure_public_key=closure_public,
        expected_nonce=kwargs.pop("expected_nonce", "request-123"),
        expected_adapter_id=kwargs.pop(
            "expected_adapter_id", "frequency.generated-artifact-world.v1"
        ),
        **kwargs,
    )


def _codes(result):
    return {item["code"] for item in result["findings"]}


def test_valid_portable_bundle_verifies_without_strengthening_claim():
    bundle, observer_public, closure_public, bundle_public = _case()

    result = _verify(bundle, observer_public, closure_public, bundle_public)

    assert result["status"] == "VERIFIED"
    assert result["bundle_signature_verified"] is True
    assert result["content_conformance"]["status"] == "VERIFIED"
    assert result["content_conformance"]["claim_ceiling"] == (
        "externally-observed-effect-with-signed-closure"
    )


def test_run_mutation_after_bundle_signing_fails_closed():
    bundle, observer_public, closure_public, bundle_public = _case()
    bundle["run"]["execution"]["request"]["mode"] = "replace"

    result = _verify(bundle, observer_public, closure_public, bundle_public)

    assert result["status"] == "NOT VERIFIED"
    assert "BUNDLE_RUN_DIGEST_MISMATCH" in _codes(result)
    assert "BUNDLE_SIGNATURE_NOT_VERIFIED" in _codes(result)


def test_bundle_metadata_substitution_breaks_identity_and_signature():
    bundle, observer_public, closure_public, bundle_public = _case()
    bundle["adapter_id"] = "frequency.other-adapter.v1"

    result = _verify(bundle, observer_public, closure_public, bundle_public)

    assert "BUNDLE_ADAPTER_MISMATCH" in _codes(result)
    assert "BUNDLE_ID_MISMATCH" in _codes(result)
    assert "BUNDLE_SIGNATURE_NOT_VERIFIED" in _codes(result)


def test_wrong_bundle_signing_key_fails_closed():
    bundle, observer_public, closure_public, _ = _case()
    _, wrong_public = _keypair()

    result = _verify(bundle, observer_public, closure_public, wrong_public)

    assert result["status"] == "NOT VERIFIED"
    assert "BUNDLE_SIGNATURE_NOT_VERIFIED" in _codes(result)


def test_nonce_mismatch_is_not_freshness_verified():
    bundle, observer_public, closure_public, bundle_public = _case()

    result = _verify(
        bundle,
        observer_public,
        closure_public,
        bundle_public,
        expected_nonce="request-999",
    )

    assert result["status"] == "NOT VERIFIED"
    assert "BUNDLE_NONCE_MISMATCH" in _codes(result)


def test_caller_seen_set_can_fail_closed_on_replay():
    bundle, observer_public, closure_public, bundle_public = _case()

    result = _verify(
        bundle,
        observer_public,
        closure_public,
        bundle_public,
        seen_bundle_ids={bundle["bundle_id"]},
    )

    assert result["status"] == "NOT VERIFIED"
    assert "BUNDLE_REPLAY_DETECTED" in _codes(result)


def test_valid_bundle_signature_cannot_promote_invalid_inner_evidence():
    bundle, observer_public, closure_public, bundle_public = _case()
    tampered = deepcopy(bundle["run"])
    tampered["observation"]["effect_digest"] = "sha256:" + "9" * 64

    bundle_private, bundle_public2 = _keypair()
    rewrapped = create_bundle(
        tampered,
        issuer_id="issuer://altru.dev/frequency",
        issued_at=1001,
        nonce="request-456",
        adapter_id="frequency.generated-artifact-world.v1",
        source_commit="7af2d900ffe17be880127fba902f940c7e6d41c8",
        signing_key=bundle_private,
    )

    result = verify_bundle(
        rewrapped,
        trusted_issuer_id="issuer://altru.dev/frequency",
        trusted_bundle_public_key=bundle_public2,
        trusted_observer_id="observer://portable/demo",
        trusted_observer_public_key=observer_public,
        trusted_closure_public_key=closure_public,
        expected_nonce="request-456",
        expected_adapter_id="frequency.generated-artifact-world.v1",
    )

    assert result["bundle_signature_verified"] is True
    assert result["status"] == "NOT VERIFIED"
    assert "BUNDLE_CONTENT_NOT_VERIFIED" in _codes(result)


def test_bundle_cannot_supply_its_own_trust_roots():
    bundle, observer_public, closure_public, bundle_public = _case()
    bundle["trusted_bundle_public_key"] = "attacker-controlled"
    bundle["trusted_observer_public_key"] = "attacker-controlled"

    result = _verify(bundle, observer_public, closure_public, bundle_public)

    assert result["status"] == "NOT VERIFIED"
    assert "UNEXPECTED_BUNDLE_FIELD" in _codes(result)
    assert result["bundle_signature_verified"] is True


def test_source_commit_can_be_pinned_by_verifier():
    bundle, observer_public, closure_public, bundle_public = _case()

    result = verify_bundle(
        bundle,
        trusted_issuer_id="issuer://altru.dev/frequency",
        trusted_bundle_public_key=bundle_public,
        trusted_observer_id="observer://portable/demo",
        trusted_observer_public_key=observer_public,
        trusted_closure_public_key=closure_public,
        expected_nonce="request-123",
        expected_adapter_id="frequency.generated-artifact-world.v1",
        expected_source_commit="deadbeef",
    )

    assert result["status"] == "NOT VERIFIED"
    assert "BUNDLE_SOURCE_COMMIT_MISMATCH" in _codes(result)


def test_create_bundle_freezes_run_copy():
    observer_private, _ = _keypair()
    closure_private, _ = _keypair()
    bundle_private, _ = _keypair()
    run = _run()
    _seal_run(run, observer_private, closure_private)

    bundle = create_bundle(
        run,
        issuer_id="issuer://altru.dev/frequency",
        issued_at=1000,
        nonce="freeze-test",
        adapter_id="frequency.generated-artifact-world.v1",
        source_commit="7af2d900ffe17be880127fba902f940c7e6d41c8",
        signing_key=bundle_private,
    )
    run["execution"]["request"]["mode"] = "replace"

    assert bundle["run"]["execution"]["request"]["mode"] == "publish"


def test_valid_signature_from_unexpected_issuer_is_not_authorized():
    observer_private, observer_public = _keypair()
    closure_private, closure_public = _keypair()
    bundle_private, bundle_public = _keypair()
    run = _run()
    _seal_run(run, observer_private, closure_private)

    bundle = create_bundle(
        run,
        issuer_id="issuer://other",
        issued_at=1000,
        nonce="request-other",
        adapter_id="frequency.generated-artifact-world.v1",
        source_commit="7af2d900ffe17be880127fba902f940c7e6d41c8",
        signing_key=bundle_private,
    )

    result = verify_bundle(
        bundle,
        trusted_issuer_id="issuer://altru.dev/frequency",
        trusted_bundle_public_key=bundle_public,
        trusted_observer_id="observer://portable/demo",
        trusted_observer_public_key=observer_public,
        trusted_closure_public_key=closure_public,
        expected_nonce="request-other",
        expected_adapter_id="frequency.generated-artifact-world.v1",
    )

    assert result["bundle_signature_verified"] is True
    assert result["status"] == "NOT VERIFIED"
    assert "BUNDLE_ISSUER_NOT_TRUSTED" in _codes(result)
