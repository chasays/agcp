# AGCP MVP (Rust)

An end-to-end AGCP minimum viable implementation, including:
- Policy Engine
- Capability Tokens (Ed25519)
- Tool Gateway (mock)
- Audit Ledger (append-only WAL + hash chain)
- Governor (kill/degrade)
- Human Approval

## Repository Layout

- `src/proto.rs`: Core protocol types
- `src/crypto.rs`: JSON+JCS, signing/verification, hashing
- `src/policy.rs`: Policy evaluation and budget controls
- `src/token.rs`: Capability token issue/verify
- `src/governor.rs`: Kill/degrade state machine
- `src/gateway.rs`: Tool gateway and mock execution
- `src/ledger.rs`: WAL and chain integrity verification
- `src/api.rs`: HTTP API
- `config/policy.devops.toml`: DevOps policy template
- `scripts/regression.sh`: 6-scenario regression script

## Start

1. Install Rust stable (`rustup`, `cargo`).
2. Run in the project directory:

```bash
cargo run
```

Service address: `http://127.0.0.1:8080`

## API

- `POST /v1/actions/submit`
- `POST /v1/actions/:action_id/approve`
- `POST /v1/governor/kill`
- `POST /v1/governor/degrade`
- `GET /v1/audit/:action_id`
- `GET /v1/health`

## Generate Signed Request Samples

```bash
cargo run --example make_payload -- low act-low-1 run-low
cargo run --example make_payload -- high act-esc-1 run-esc
cargo run --example make_payload -- read_only_write act-ro-1 run-ro
```

## Regression Script

Start the service first, then run:

```bash
./scripts/regression.sh
```

The script covers:
1. Health check
2. Low-risk direct execution
3. High-risk escalation
4. Human approval execution
5. Write action blocked in read-only mode
6. Audit lookup

## Current Limitations

- `runtime_attestation` is a placeholder only; no real TEE attestation is implemented.
- Tool execution is mocked and does not touch production systems.
- Single-process, single-node deployment; no distributed consistency.
- Keys are managed as local files (`data/policy_signing_key.b64`).
