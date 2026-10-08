# Retained verifier context: exploratory v1

Tracks #8. This is an **internal research fixture**, not TRACE conformance, a signed TRACE extension, a full verifier, or a production trust decision.

## Demonstrated boundary

A record that establishes `pcr:2` but not `pcr:3` can satisfy a policy requiring only `pcr:2`, while the same record cannot satisfy a policy requiring both. Without retained policy context, replay must not infer an affirming appraisal. This models the verifier-side dependency explicitly acknowledged in agentrust-io/trace-spec#477.

The fixed-time check models only the `iat` freshness comparison described in agentrust-io/trace-spec#480. It does **not** validate a signature, inclusion proof, historical revocation, trusted timestamps, resolver contents, or the provenance of the policy. A `context-checks-satisfied` result is **not** a TRACE verification success.

## Limitations and next gate

This first fixture uses restricted deterministic JSON, **not RFC 8785/JCS**. The digest binds supplied context bytes but does not authenticate them. The retained required-layer policy is now bound to its deterministic fixture digest, but the policy's provenance and authority are not authenticated. Trust-root and resolver hashes remain opaque placeholders, not verified snapshots. The next implementation must authenticate policy provenance, verify trust and inclusion evidence independently, pin actual resolver responses, use a proven canonicalizer, add independent cross-language vectors, and prove the output against TRACE's normative schema and conformance corpus before any upstream proposal.

Run: `python -m unittest discover -s tests -p test_trace_context.py -v`.
