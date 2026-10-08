import unittest
from trace_context.envelope import assess, digest, receipt

RECORD = {"iat": 100, "appraisal": {"platform_measurement": {"layers": {
    "pcr:2": {"outcome": "established"},
    "pcr:3": {"outcome": "not-established", "reason": "measured-not-appraised"}}}}}
POLICY = {"required_layers": ["pcr:2"]}
BASE = {"verified_at": 110, "max_age_seconds": 30, "max_future_skew_seconds": 2,
        "policy_sha256": digest(POLICY), "policy": POLICY, "required_layers": ["pcr:2"],
        "trust_roots_sha256": "roots-fixture", "resolver_snapshot_sha256": "resolver-fixture",
        "verifier_revision": "fixture-v1", "record_sha256": digest(RECORD)}

class RetainedContextTests(unittest.TestCase):
    def test_policy_differential(self):
        self.assertEqual(assess(RECORD, BASE)["status"], "context-checks-satisfied")
        policy = {"required_layers": ["pcr:2", "pcr:3"]}
        changed = dict(BASE, required_layers=policy["required_layers"], policy=policy, policy_sha256=digest(policy))
        self.assertEqual(assess(RECORD, changed)["reason"], "required-layer-not-established")

    def test_missing_policy_fails_closed(self):
        context = dict(BASE)
        del context["policy_sha256"]
        self.assertEqual(assess(RECORD, context)["reason"], "missing-context")

    def test_missing_required_layer_fails_closed(self):
        policy = {"required_layers": ["pcr:4"]}
        context = dict(BASE, required_layers=policy["required_layers"], policy=policy, policy_sha256=digest(policy))
        self.assertEqual(assess(RECORD, context)["status"], "not-established")

    def test_freshness_boundaries(self):
        self.assertEqual(assess(RECORD, dict(BASE, verified_at=130))["status"], "context-checks-satisfied")
        self.assertEqual(assess(RECORD, dict(BASE, verified_at=131))["reason"], "freshness-window")
        self.assertEqual(assess(RECORD, dict(BASE, verified_at=98))["status"], "context-checks-satisfied")
        self.assertEqual(assess(RECORD, dict(BASE, verified_at=97))["reason"], "freshness-window")

    def test_mutation_breaks_binding(self):
        mutated = dict(RECORD, iat=101)
        self.assertEqual(assess(mutated, BASE)["reason"], "record-binding-mismatch")

    def test_receipt_is_deterministic(self):
        self.assertEqual(receipt(RECORD, BASE), receipt(RECORD, BASE))
        self.assertNotEqual(receipt(RECORD, BASE)["sha256"], receipt(RECORD, dict(BASE, policy_sha256="different"))["sha256"])

    def test_malformed_time_fails_closed(self):
        for value in (110.5, "110", True, None):
            self.assertEqual(assess(RECORD, dict(BASE, verified_at=value))["reason"], "invalid-time-context")

    def test_absent_measurement_fails_closed(self):
        record = {"iat": 100}
        context = dict(BASE, record_sha256=digest(record))
        self.assertEqual(assess(record, context)["reason"], "missing-layer-evidence")

    def test_empty_policy_fails_closed(self):
        self.assertEqual(assess(RECORD, dict(BASE, required_layers=[]))["reason"], "empty-required-layer-policy")

    def test_policy_digest_mutation_fails_closed(self):
        self.assertEqual(assess(RECORD, dict(BASE, policy_sha256="tampered"))["reason"], "policy-binding-mismatch")

    def test_policy_layer_mismatch_fails_closed(self):
        self.assertEqual(assess(RECORD, dict(BASE, required_layers=["pcr:3"]))["reason"], "policy-content-mismatch")

if __name__ == "__main__":
    unittest.main()
