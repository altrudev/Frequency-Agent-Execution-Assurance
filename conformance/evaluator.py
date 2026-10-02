from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "frequency.execution-conformance.v1"
VERIFIED_CEILING = "externally-observed-effect-with-signed-closure"
PARTIAL_CEILING = "execution-or-observation-only"
NOT_VERIFIED_CEILING = "not-verified"


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def observation_payload(run: dict[str, Any]) -> dict[str, Any]:
    observation = run.get("observation") if isinstance(run.get("observation"), dict) else {}
    return {
        "observer_id": observation.get("observer_id"),
        "independent": observation.get("independent"),
        "target": observation.get("target"),
        "operation": observation.get("operation"),
        "effect_digest": observation.get("effect_digest"),
        "observed_at": observation.get("observed_at"),
    }


def closure_payload(run: dict[str, Any]) -> dict[str, Any]:
    evidence = run.get("evidence") if isinstance(run.get("evidence"), dict) else {}
    return {
        "schema": run.get("schema"),
        "intent": run.get("intent"),
        "authority": run.get("authority"),
        "execution": run.get("execution"),
        "observation": run.get("observation"),
        "required_refs": evidence.get("required_refs"),
        "refs": evidence.get("refs"),
        "observer_attestation": evidence.get("observer_attestation"),
    }


def _add(findings: list[dict[str, str]], code: str, detail: str) -> None:
    findings.append({"code": code, "detail": detail})


def _verify_signature(
    attestation: dict[str, Any],
    payload_digest: str,
    trusted_public_key: bytes | None,
) -> bool:
    if trusted_public_key is None:
        return False
    signature_b64 = attestation.get("signature")
    if not isinstance(signature_b64, str) or not signature_b64:
        return False
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(
            signature, payload_digest.encode("ascii")
        )
    except (ValueError, InvalidSignature):
        return False
    return True
def evaluate_run(
    run: dict[str, Any],
    *,
    trusted_observer_id: str | None = None,
    trusted_observer_public_key: bytes | None = None,
    trusted_closure_public_key: bytes | None = None,
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []

    for field in ("intent", "authority", "execution", "observation", "evidence"):
        if not isinstance(run.get(field), dict):
            _add(findings, "MISSING_SECTION", f"{field} must be an object")

    if findings:
        return _result(findings, False, False, False)

    intent = run["intent"]
    authority = run["authority"]
    execution = run["execution"]
    observation = run["observation"]
    evidence = run["evidence"]

    request = execution.get("request")
    if not isinstance(request, dict):
        _add(findings, "MISSING_EXECUTION_REQUEST", "execution.request must be an object")
        request_digest = None
    else:
        request_digest = digest(request)

    for field in ("principal", "target", "operation"):
        expected = authority.get(field)
        if expected != execution.get(field):
            _add(
                findings,
                "AUTHORITY_BINDING_MISMATCH",
                f"execution.{field} does not match authority.{field}",
            )

    if request_digest is not None and authority.get("request_digest") != request_digest:
        _add(
            findings,
            "AUTHORIZED_REQUEST_MUTATED",
            "execution request differs from the request digest bound by authority",
        )

    started_at = execution.get("started_at")
    valid_from = authority.get("valid_from")
    valid_until = authority.get("valid_until")
    if not all(isinstance(v, int) for v in (started_at, valid_from, valid_until)):
        _add(findings, "INVALID_AUTHORITY_TIME", "authority/execution times must be integers")
    elif not (valid_from <= started_at <= valid_until):
        _add(
            findings,
            "STALE_OR_PREMATURE_AUTHORITY",
            "execution occurred outside the authority validity window",
        )

    if intent.get("principal") != authority.get("principal"):
        _add(findings, "INTENT_PRINCIPAL_MISMATCH", "intent principal is not authority principal")
    if intent.get("target") != authority.get("target"):
        _add(findings, "INTENT_TARGET_MISMATCH", "intent target is not authority target")
    if intent.get("operation") != authority.get("operation"):
        _add(findings, "INTENT_OPERATION_MISMATCH", "intent operation is not authority operation")

    observation_ok = True
    if observation.get("independent") is not True:
        observation_ok = False
        _add(findings, "OBSERVER_NOT_INDEPENDENT", "observation is not marked independent")
    if observation.get("observer_id") == execution.get("principal"):
        observation_ok = False
        _add(findings, "SELF_OBSERVATION", "execution principal cannot satisfy independent observation")
    if not isinstance(trusted_observer_id, str) or not trusted_observer_id:
        observation_ok = False
        _add(
            findings,
            "OBSERVER_ID_NOT_TRUSTED",
            "a trusted observer identity must be supplied independently",
        )
    elif observation.get("observer_id") != trusted_observer_id:
        observation_ok = False
        _add(
            findings,
            "OBSERVER_ID_NOT_TRUSTED",
            "observation observer_id does not match the trusted observer identity",
        )
    observed_at = observation.get("observed_at")
    if not isinstance(observed_at, int):
        observation_ok = False
        _add(
            findings,
            "INVALID_OBSERVATION_TIME",
            "observation.observed_at must be an integer",
        )
    elif isinstance(started_at, int) and observed_at < started_at:
        observation_ok = False
        _add(
            findings,
            "OBSERVATION_PRECEDES_EXECUTION",
            "independent observation cannot precede execution start",
        )

    for field in ("target", "operation", "effect_digest"):
        if observation.get(field) != execution.get(field):
            observation_ok = False
            _add(
                findings,
                "OBSERVATION_CORRELATION_MISMATCH",
                f"observation.{field} does not match execution.{field}",
            )

    observer_attestation = evidence.get("observer_attestation")
    observer_signature_ok = False
    if not isinstance(observer_attestation, dict):
        observation_ok = False
        _add(
            findings,
            "MISSING_OBSERVER_ATTESTATION",
            "independent observation requires a trusted observer attestation",
        )
    else:
        expected_observation_digest = digest(observation_payload(run))
        if observer_attestation.get("payload_digest") != expected_observation_digest:
            observation_ok = False
            _add(
                findings,
                "OBSERVER_ATTESTATION_DIGEST_MISMATCH",
                "observer attestation does not bind the current observation",
            )
        elif not _verify_signature(
            observer_attestation,
            expected_observation_digest,
            trusted_observer_public_key,
        ):
            observation_ok = False
            _add(
                findings,
                "OBSERVER_SIGNATURE_NOT_VERIFIED",
                "observer signature is absent or invalid for the trusted observer key",
            )
        else:
            observer_signature_ok = True

    refs = evidence.get("refs")
    required_refs = evidence.get("required_refs")
    refs_ok = isinstance(refs, dict) and isinstance(required_refs, list)
    if not refs_ok:
        _add(findings, "INVALID_EVIDENCE_REFS", "evidence refs/required_refs are malformed")
    else:
        for ref in required_refs:
            if not isinstance(ref, str) or not isinstance(refs.get(ref), str) or not refs.get(ref):
                _add(findings, "MISSING_REQUIRED_EVIDENCE", f"required evidence ref missing: {ref}")

    closure = evidence.get("closure")
    signed_closure_ok = False
    if not isinstance(closure, dict):
        _add(findings, "MISSING_CLOSURE", "signed closing commitment is required")
    else:
        expected_payload_digest = digest(closure_payload(run))
        if closure.get("payload_digest") != expected_payload_digest:
            _add(findings, "CLOSURE_DIGEST_MISMATCH", "closing commitment does not bind current evidence")
        elif not _verify_signature(
            closure, expected_payload_digest, trusted_closure_public_key
        ):
            _add(findings, "CLOSURE_SIGNATURE_NOT_VERIFIED", "closing signature is absent or invalid")
        else:
            signed_closure_ok = True

    blocking_codes = {
        "MISSING_EXECUTION_REQUEST",
        "AUTHORITY_BINDING_MISMATCH",
        "AUTHORIZED_REQUEST_MUTATED",
        "STALE_OR_PREMATURE_AUTHORITY",
        "INVALID_AUTHORITY_TIME",
        "INTENT_PRINCIPAL_MISMATCH",
        "INTENT_TARGET_MISMATCH",
        "INTENT_OPERATION_MISMATCH",
        "MISSING_REQUIRED_EVIDENCE",
    }
    effect_verified = (
        observation_ok
        and observer_signature_ok
        and refs_ok
        and signed_closure_ok
        and not any(f["code"] in blocking_codes for f in findings)
    )

    claims = run.get("claims") if isinstance(run.get("claims"), dict) else {}
    if claims.get("external_effect_verified") is True and not effect_verified:
        _add(
            findings,
            "CLAIM_EXCEEDS_EVIDENCE",
            "run claims external-effect verification above the supported evidence ceiling",
        )

    return _result(
        findings,
        effect_verified,
        observer_signature_ok,
        signed_closure_ok,
    )


def _result(
    findings: list[dict[str, str]],
    effect_verified: bool,
    observer_signature_ok: bool,
    signed_closure_ok: bool,
) -> dict[str, Any]:
    if effect_verified:
        status = "VERIFIED"
        ceiling = VERIFIED_CEILING
    elif signed_closure_ok:
        status = "NOT VERIFIED"
        ceiling = PARTIAL_CEILING
    else:
        status = "NOT VERIFIED"
        ceiling = NOT_VERIFIED_CEILING
    return {
        "schema": SCHEMA,
        "status": status,
        "claim_ceiling": ceiling,
        "external_effect_verified": effect_verified,
        "observer_signature_verified": observer_signature_ok,
        "signed_closure_verified": signed_closure_ok,
        "findings": findings,
    }
