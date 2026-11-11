# Changelog

All notable changes to `CascadeAttestationGraph` are documented in this file.

## [1.0.0] - 2026-11-11
### Added
- Implemented `CascadeAttestationGraph` GenVM Intelligent Contract (`CascadeAttestationGraph.py`).
- Added DAG topological cycle detection (`_creates_cycle`) and downstream dependent traversal (`_collect_downstream_dependents`).
- Implemented strict HTTPS URI canonicalization and trusted host allowlisting (`_normalize_https_uri`).
- Added 8-field `AdjudicationSeal` multi-validator equivalence consensus (`gl.vm.run_nondet_unsafe`) with verbatim excerpt grounding (`_excerpt_anchored_in_artifact`).
- Implemented Selective Cascade Revocation Propagation (`revoke_vertex`) that freezes compromised subgraphs while preserving disjoint branches.
- Added strict vault conservation-of-funds invariant checks (`_verify_vault_conservation`) across `unallocated`, `escrowed`, `frozen`, and `disbursed` buckets.
- Added unit and end-to-end test suite (`test_cascade_attestation_graph.py`) and benchmark dataset (`sample_dataset.json`).
