# Portable Evidence Bundle v1

The public conformance layer can package one execution-evidence run into a signed, portable JSON bundle for offline verification.

Schema:

`frequency.portable-evidence-bundle.v1`

The bundle exists to preserve provenance and integrity across transport. It does **not** create a stronger assurance claim than the evidence inside it.

## Trust model

A verifier supplies trust independently:

- expected bundle issuer identity;
- trusted bundle issuer Ed25519 public key;
- trusted observer identity;
- trusted observer Ed25519 public key;
- trusted closing Ed25519 public key.

Trust roots are never accepted from the bundle itself. Unexpected top-level fields fail closed.

The bundle signature proves only that the signed package was produced by the holder of the trusted bundle key and was not changed afterward.

The inner Frequency conformance run is then re-evaluated separately. A valid bundle signature cannot promote invalid or incomplete execution evidence.

## Bound fields

The signed payload binds:

- bundle schema;
- deterministic bundle ID;
- issuer identity;
- issue time;
- nonce / caller challenge;
- adapter ID;
- source commit;
- exact run digest;
- complete run envelope.

The bundle ID is derived from issuer, issue time, nonce, adapter, source commit, and run digest.

## Freshness and replay

Offline signatures do not prove freshness on their own.

The verifier therefore supports:

- an expected nonce/challenge;
- an exact expected adapter ID;
- an exact expected source commit;
- caller-supplied previously seen bundle IDs.

A nonce mismatch, source mismatch, adapter mismatch, or known bundle ID returns `NOT VERIFIED`.

The reference verifier does not persist replay state. A production caller must maintain its own challenge and seen-ID state when replay resistance matters.

## Claim ceiling

A bundle is `VERIFIED` only when both are true:

1. the portable bundle passes its own issuer/integrity/context checks; and
2. the contained execution evidence independently reaches the public Frequency `VERIFIED` ceiling.

If the bundle signature is valid but the inner execution evidence is not, the result remains `NOT VERIFIED`.

This means the bundle does not convert:

- a tool response into proof of external state;
- an AYA Receipt into independent observation;
- a TRACE signature into runtime-attestation binding;
- a Thrixel reference call into proof of vendor execution.

## Offline verification

```bash
python -m conformance.bundle_cli evidence-bundle.json \
  --issuer-id issuer://altru.dev/frequency \
  --bundle-key bundle-issuer.pub \
  --observer-id observer://independent/example \
  --observer-key observer.pub \
  --closure-key closure.pub \
  --expected-nonce request-123 \
  --expected-adapter frequency.generated-artifact-world.v1 \
  --expected-source-commit <exact-commit-sha>
```

The CLI exits with status `0` only for `VERIFIED`; `NOT VERIFIED` exits with status `2`.

Use `--seen-bundle-id` one or more times when the caller maintains replay state.

## Public/private boundary

The portable bundle contains public evidence-contract material only. It does not require or expose:

- Frequency Core policy internals;
- private enforcement logic;
- raw credentials;
- secret keys;
- proprietary analysis state.

Private keys remain outside the bundle. Only signatures and public evidence are portable.
