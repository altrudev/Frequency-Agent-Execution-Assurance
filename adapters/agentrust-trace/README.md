# Frequency Agent Execution Assurance — TRACE Adapter

This small public adapter verifies a standalone AgenTrust TRACE Trust Record with a caller-supplied trusted issuer key and projects selected verified fields into the public Frequency evidence contract.

It does **not** expose Frequency Core and does not grant execution authority.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r adapters/agentrust-trace/requirements.txt
python adapters/agentrust-trace/demo.py
pytest -q adapters/agentrust-trace/tests
```

The demo creates a temporary signed TRACE record using the released `agentrust-trace` package, verifies it with an independently supplied JWK file, and prints a Frequency external-evidence projection.

## Verified scope

The adapter verifies the standalone TRACE record using the released TRACE verifier and a caller-supplied trusted key. The emitted projection preserves hashes for the exact record and trusted-key files and carries an explicit claim ceiling.

The projection does not claim that:
- the trusted signing key was independently bound to the runtime measurement or attestation it accompanies;
- a hardware attestation was independently verified;
- a transparency/registry inclusion proof was independently verified;
- the content behind a tool-transcript hash was independently bound;
- an external tool call or durable state mutation occurred;
- Frequency Core authorized or executed the action.

This adapter directory is Apache-2.0 licensed. Frequency Core and the broader product remain proprietary.
