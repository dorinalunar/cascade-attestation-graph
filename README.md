# CascadeAttestationGraph

**DAG-Based Attestation Escrow & Selective Cascade Revocation Engine on GenLayer (GenVM)**

`CascadeAttestationGraph` is a GenLayer Intelligent Contract that coordinates multi-stage milestone escrow settlements over a Directed Acyclic Graph (DAG) of external evidence attestations. It combines HTTPS host-allowlisted evidence fetching, verbatim quote grounding, 8-field validator equivalence consensus, and selective cascade revocation propagation with strict conservation-of-funds accounting.

---

## Core Capabilities

- **Topological Dependency Graph & Cycle Prevention**: Supports atomic `ATTESTATION` vertices (`vertex_kind = 1`) and derived `MILESTONE` vertices (`vertex_kind = 2`) with cycle detection (`_creates_cycle`) and upstream prerequisite enforcement.
- **8-Field AdjudicationSeal Consensus**: Uses `gl.vm.run_nondet_unsafe` to require independent validators to agree 1:1 on `http_code`, `artifact_sha256`, discrete `verdict` (`CONFIRMED`, `REFUTED`, `INDETERMINATE`), normalized verbatim `excerpt`, and `audit_code`.
- **Selective Cascade Revocation Propagation**: If an active upstream attestation is revoked via verified security advisory (`revoke_vertex`), the target vertex transitions to `STATE_REVOKED` and all reachable downstream dependents automatically transition to `STATE_CASCADE_HALTED` with their escrowed funds moved to `vault_frozen_wei` — while independent DAG branches remain unaffected and settleable.
- **Vault Conservation Invariant**: Enforces `_verify_vault_conservation()` on every write operation across `unallocated`, `escrowed`, `frozen`, and `disbursed` accounting buckets.

---

## Repository Structure

```text
├── .github/workflows/ci.yml            # Automated pytest CI workflow
├── .env.example                        # GenLayer Studio RPC & configuration template
├── .gitignore                          # Python & environment ignores
├── CHANGELOG.md                        # Release history
├── CONTRIBUTING.md                     # Contributor guidelines
├── CascadeAttestationGraph.py          # GenVM Intelligent Contract
├── LICENSE                             # MIT License
├── README.md                           # Architecture & interface documentation
├── SECURITY.md                         # Threat model & invariant specifications
├── requirements.txt                    # Test suite dependencies
├── sample_dataset.json                 # End-to-end DAG & cascade revocation vectors
└── test_cascade_attestation_graph.py   # Pytest unit & e2e consensus test suite
```

---

## Contract Interface

### Constructor
- `__init__(trusted_hosts_list: DynArray[str])` — Initializes the graph governor and binds the allowlist of trusted HTTPS domains (e.g., `["raw.githubusercontent.com", "security.genlayer.io"]`).

### Payable & Write Methods
- `fund_vault() -> None` *(payable)* — Deposits native value into the caller's sponsor credit and `vault_unallocated_wei`.
- `register_vertex(vertex_id, vertex_kind, upstream_ids, artifact_uri, claim_scope, escrowed_wei, beneficiary) -> None` — Registers an attestation or derived milestone vertex in the DAG and locks sponsor escrow.
- `verify_vertex(vertex_id: str) -> dict` — Verifies upstream prerequisites and executes GenVM LLM consensus for attestation vertices or deterministic activation for derived milestones.
- `revoke_vertex(vertex_id: str, revocation_uri: str) -> dict` — Evaluates revocation evidence and, if `CONFIRMED`, halts the target vertex and all downstream dependents while freezing their escrow.
- `settle_vertex(vertex_id: str) -> u256` — Disburses escrowed funds to `beneficiary` via `_EvmPayoutTarget` once the vertex is in `STATE_VERIFIED`.
- `reclaim_frozen_escrow(vertex_id: str) -> None` — Returns frozen escrow from `STATE_REVOKED` or `STATE_CASCADE_HALTED` vertices back to the sponsor's unallocated vault balance.

### View Methods
- `protocol_version() -> str` — Returns `"CascadeAttestationGraph/v1.0"`.
- `get_vertex(vertex_id: str) -> dict` — Returns full vertex metadata, lifecycle state, and adjudication seal telemetry.
- `get_vault_telemetry() -> dict` — Returns vault bucket balances (`unallocated`, `escrowed`, `frozen`, `disbursed`, `inflow`, `outflow`, `vertex_count`).
- `is_vertex_settleable(vertex_id: str) -> bool` — Returns `True` if `vertex_id` is currently in `STATE_VERIFIED`.

---

## Running Tests Locally

```bash
pip install -r requirements.txt
pytest -v
```
