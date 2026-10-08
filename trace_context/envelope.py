"""Independent, non-normative retained verifier context contract."""
import hashlib
import json

REQUIRED = ("record_sha256", "verified_at", "max_age_seconds", "max_future_skew_seconds",
            "policy_sha256", "required_layers", "trust_roots_sha256",
            "resolver_snapshot_sha256", "verifier_revision")

def canonical(value):
    """Deterministic JSON for restricted ASCII-key test fixtures; not RFC 8785."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def assess(record, context):
    missing = [key for key in REQUIRED if key not in context]
    if missing:
        return {"status": "not-established", "reason": "missing-context", "missing": missing}
    if not isinstance(context["required_layers"], list) or not all(isinstance(x, str) for x in context["required_layers"]):
        return {"status": "not-established", "reason": "invalid-policy"}
    if not context["required_layers"]:
        return {"status": "not-established", "reason": "empty-required-layer-policy"}
    if len(set(context["required_layers"])) != len(context["required_layers"]):
        return {"status": "not-established", "reason": "duplicate-required-layer"}
    policy = context.get("policy")
    if not isinstance(policy, dict) or set(policy) != {"required_layers"} or policy["required_layers"] != context["required_layers"]:
        return {"status": "not-established", "reason": "policy-content-mismatch"}
    if digest(policy) != context["policy_sha256"]:
        return {"status": "not-established", "reason": "policy-binding-mismatch"}
    if digest(record) != context["record_sha256"]:
        return {"status": "not-established", "reason": "record-binding-mismatch"}
    try:
        if not all(type(v) is int for v in (context["verified_at"], record["iat"], context["max_age_seconds"], context["max_future_skew_seconds"])):
            raise ValueError()
        now, issued = context["verified_at"], record["iat"]
        age, skew = context["max_age_seconds"], context["max_future_skew_seconds"]
        if any(isinstance(context[k], bool) for k in ("verified_at", "max_age_seconds", "max_future_skew_seconds")) or age < 0 or skew < 0:
            raise ValueError()
    except (ValueError, TypeError, KeyError):
        return {"status": "not-established", "reason": "invalid-time-context"}
    if issued < now - age or issued > now + skew:
        return {"status": "rejected", "reason": "freshness-window"}
    appraisal = record.get("appraisal")
    measurement = appraisal.get("platform_measurement") if isinstance(appraisal, dict) else None
    layers = measurement.get("layers") if isinstance(measurement, dict) else None
    if not isinstance(layers, dict):
        return {"status": "not-established", "reason": "missing-layer-evidence"}
    absent = [name for name in context["required_layers"] if not isinstance(layers.get(name), dict) or layers[name].get("outcome") != "established"]
    if absent:
        return {"status": "not-established", "reason": "required-layer-not-established", "layers": absent}
    return {"status": "context-checks-satisfied", "reason": "limited-local-evaluation"}

def receipt(record, context):
    """Bind inputs and limited evaluation, without claiming signature or trust verification."""
    result = assess(record, context)
    payload = {"contract": "frequency-retained-context-v1", "record_sha256": digest(record),
               "context_sha256": digest(context), "result": result}
    return {"payload": payload, "sha256": digest(payload)}
