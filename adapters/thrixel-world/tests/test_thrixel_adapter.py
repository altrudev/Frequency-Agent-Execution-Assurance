from __future__ import annotations

import base64
import importlib.util
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[3]
ADAPTER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location(
    "frequency_thrixel_world_adapter", ADAPTER_DIR / "adapter.py"
)
assert spec is not None and spec.loader is not None
thrixel_adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(thrixel_adapter)

ThrixelProfileError = thrixel_adapter.ThrixelProfileError
build_conformance_run = thrixel_adapter.build_conformance_run
load_profile = thrixel_adapter.load_profile
prepare_call = thrixel_adapter.prepare_call
validate_profile = thrixel_adapter.validate_profile

from conformance import closure_payload, digest, evaluate_run, observation_payload

PROFILE = ADAPTER_DIR / "fixtures" / "profile.json"


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


def _attest(private: Ed25519PrivateKey, payload_digest: str) -> dict:
    signature = private.sign(payload_digest.encode("ascii"))
    return {
        "payload_digest": payload_digest,
        "signature": base64.b64encode(signature).decode("ascii"),
        "algorithm": "Ed25519",
    }


def _prepared() -> dict:
    profile = load_profile(PROFILE)
    return prepare_call(
        profile,
        "thrixel_create_model",
        {"project": "harbor-game", "prompt": "three-masted pirate ship"},
    )


def _run() -> dict:
    return build_conformance_run(
        profile=load_profile(PROFILE),
        prepared_call=_prepared(),
        principal="agent://demo-builder",
        target="thrixel://project/harbor-game/asset/pirate-ship",
        valid_from=100,
        valid_until=200,
        started_at=150,
        effect_digest="sha256:" + "e" * 64,
        observer_id="observer://independent/thrixel-demo",
        observed_at=155,
        observation_effect_digest="sha256:" + "e" * 64,
        execution_receipt="sha256:" + "1" * 64,
        observation_receipt="sha256:" + "2" * 64,
    )


def _seal(run: dict, observer_private, closure_private) -> None:
    run["evidence"]["observer_attestation"] = _attest(
        observer_private, digest(observation_payload(run))
    )
    run["evidence"]["closure"] = _attest(
        closure_private, digest(closure_payload(run))
    )


def test_reference_profile_is_pinned_and_non_executing():
    profile = load_profile(PROFILE)
    assert profile["transport"]["package"] == "thrixel-mcp"
    assert profile["transport"]["version"] == "1.3.17"
    assert profile["transport"]["production_execution_enabled"] is False


def test_generation_call_binds_exact_tool_arguments_and_transport():
    call = _prepared()
    assert call["tool_name"] == "thrixel_create_model"
    assert call["mapped_operation"] == "artifact.generate"
    assert call["requires_independent_observation"] is True
    assert call["production_execution_enabled"] is False
    assert call["arguments_digest"] == digest(call["arguments"])


@pytest.mark.parametrize(
    "tool_name",
    [
        "thrixel_publish_game",
        "thrixel_buy_cubes",
        "thrixel_upgrade_plan",
        "thrixel_billing_portal",
    ],
)
def test_publish_and_financial_boundaries_remain_disabled(tool_name):
    profile = load_profile(PROFILE)
    with pytest.raises(ThrixelProfileError):
        prepare_call(profile, tool_name, {})


def test_mutable_transport_or_execution_enablement_fails_closed():
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    profile["transport"]["version"] = "latest"
    with pytest.raises(ThrixelProfileError):
        validate_profile(profile)

    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    profile["transport"]["production_execution_enabled"] = True
    with pytest.raises(ThrixelProfileError):
        validate_profile(profile)


def test_unknown_tool_and_non_object_arguments_fail_closed():
    profile = load_profile(PROFILE)
    with pytest.raises(ThrixelProfileError):
        prepare_call(profile, "thrixel_delete_everything", {})
    with pytest.raises(ThrixelProfileError):
        prepare_call(profile, "thrixel_create_model", "pirate ship")  # type: ignore[arg-type]


def test_thrixel_world_run_reaches_public_effect_ceiling_with_independent_evidence():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _run()
    _seal(run, observer_private, closure_private)

    result = evaluate_run(
        run,
        trusted_observer_id="observer://independent/thrixel-demo",
        trusted_observer_public_key=observer_public,
        trusted_closure_public_key=closure_public,
    )

    assert result["status"] == "VERIFIED"
    assert result["external_effect_verified"] is True
    assert result["findings"] == []


def test_argument_substitution_after_authority_fails_closed():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _run()
    _seal(run, observer_private, closure_private)
    run["execution"]["request"]["arguments"]["project"] = "other-project"

    result = evaluate_run(
        run,
        trusted_observer_id="observer://independent/thrixel-demo",
        trusted_observer_public_key=observer_public,
        trusted_closure_public_key=closure_public,
    )

    codes = {finding["code"] for finding in result["findings"]}
    assert "AUTHORIZED_REQUEST_MUTATED" in codes
    assert "CLOSURE_DIGEST_MISMATCH" in codes
    assert result["external_effect_verified"] is False


def test_vendor_success_without_correlated_external_observation_is_not_verified():
    observer_private, observer_public, closure_private, closure_public = _keys()
    run = _run()
    run["observation"]["effect_digest"] = "sha256:" + "f" * 64
    _seal(run, observer_private, closure_private)

    result = evaluate_run(
        run,
        trusted_observer_id="observer://independent/thrixel-demo",
        trusted_observer_public_key=observer_public,
        trusted_closure_public_key=closure_public,
    )

    codes = {finding["code"] for finding in result["findings"]}
    assert "OBSERVATION_CORRELATION_MISMATCH" in codes
    assert "CLAIM_EXCEEDS_EVIDENCE" in codes
    assert result["status"] == "NOT VERIFIED"


def test_public_adapter_never_promotes_reference_transport_to_live_execution():
    call = _prepared()
    tampered = deepcopy(call)
    tampered["production_execution_enabled"] = True

    with pytest.raises(ThrixelProfileError):
        build_conformance_run(
            profile=load_profile(PROFILE),
            prepared_call=tampered,
            principal="agent://demo",
            target="thrixel://asset/demo",
            valid_from=1,
            valid_until=2,
            started_at=1,
            effect_digest="sha256:" + "e" * 64,
            observer_id="observer://demo",
            observed_at=2,
            observation_effect_digest="sha256:" + "e" * 64,
            execution_receipt="sha256:" + "1" * 64,
            observation_receipt="sha256:" + "2" * 64,
        )

def test_fabricated_prepared_call_cannot_cross_into_run_builder():
    call = _prepared()
    call["mapped_operation"] = "world.publish"

    with pytest.raises(ThrixelProfileError):
        build_conformance_run(
            profile=load_profile(PROFILE),
            prepared_call=call,
            principal="agent://demo",
            target="thrixel://asset/demo",
            valid_from=1,
            valid_until=2,
            started_at=1,
            effect_digest="sha256:" + "e" * 64,
            observer_id="observer://demo",
            observed_at=2,
            observation_effect_digest="sha256:" + "e" * 64,
            execution_receipt="sha256:" + "1" * 64,
            observation_receipt="sha256:" + "2" * 64,
        )
