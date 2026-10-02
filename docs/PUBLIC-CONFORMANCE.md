# Public Execution Conformance

This repository includes a small public reference evaluator for the Frequency Agent Execution Assurance evidence boundary.

It is intentionally not Frequency Core. It does not grant authority, execute tools, store credentials, or replace a production policy engine. Its purpose is to make the public claim boundary reproducible.

## What it checks

The evaluator keeps five stages separate:

1. intent;
2. authority;
3. execution;
4. independent observation;
5. closing evidence.

A run can reach the public `externally-observed-effect-with-signed-closure` ceiling only when all required bindings hold.

The reference evaluator checks:

- signed closing commitment over the run schema and complete intent object;
- exact principal, target, and operation binding;
- exact request digest binding across authorization and execution;
- execution inside the authority validity window;
- independent observer separation from the execution principal;
- exact match to an independently supplied trusted observer identity;
- observation time at or after execution start;
- Ed25519 verification of the observation using that observer's separately supplied trusted public key;
- target, operation, and effect correlation between execution and observation;
- presence of every required evidence reference;
- a closing commitment over authority, execution, observation, and evidence references;
- Ed25519 verification of that closing commitment using a separately supplied trusted closing public key;
- attempted claims that exceed the available evidence.
## Why signed closure matters

A local hash is useful for deterministic integrity checks, but it is not sufficient to prove that an evidence chain was not rewritten by the same party that produced it.

The public evaluator therefore treats a recomputed digest as insufficient for the highest claim ceiling. The observation must verify against a trusted observer key, and the closing digest must verify against a separately supplied trusted closing key. Merely setting `independent: true` is not sufficient.

This still does not prove hardware attestation, transparency-log inclusion, physical-world state, or vendor correctness. Those remain separate evidence requirements.

## Fail-closed examples

The bundled tests cover:

- human or upstream intent exists but the execution request no longer matches the authorized digest;
- execution occurs after authority expiry;
- the execution principal tries to satisfy the independent-observer requirement itself;
- a required evidence reference is removed;
- evidence is rewritten and the local chain digest is recomputed without the trusted closing signer;
- the run claims external-effect verification above the supported evidence ceiling;
- the observed effect cannot be correlated to the executed effect.

The expected public result for those cases is `NOT VERIFIED`.

## Run the public evaluator tests

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
pytest -q tests adapters/agentrust-trace/tests
```

The human-readable adversarial corpus is in `fixtures/conformance/cases.json`.

For a self-contained successful example:

```bash
python -m conformance.demo
```

For a captured run envelope with separately supplied trusted keys:

```bash
python -m conformance.cli run.json --observer-id observer://independent/demo --observer-key observer.pub --closure-key closure.pub
```

The CLI exits with status `0` only for `VERIFIED`; `NOT VERIFIED` returns status `2`.
## Claim boundary

A `VERIFIED` result from this reference evaluator means only that the supplied public evidence satisfies this public conformance contract for the stated claim ceiling.

It does not mean:

- Frequency Core executed the action;
- a vendor or marketplace has certified the run;
- the external system is secure;
- hardware or runtime attestation is valid unless separately verified;
- a transparency service included the record unless separately verified;
- the signing key is bound to a runtime measurement unless separately verified.

Those distinctions are deliberate. Public integrations should report `NOT VERIFIED` whenever the evidence required for a stronger claim is absent.
