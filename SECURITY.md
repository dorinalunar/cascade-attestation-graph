# Security Policy & Threat Model

## Defense-in-Depth Architecture
`CascadeAttestationGraph` enforces deterministic safety across four operational boundaries:

1. **HTTPS Canonicalization & Host Allowlisting (`_normalize_https_uri`)**:
   - Rejects non-HTTPS schemes, custom ports, userinfo credentials, and path traversal sequences (`..`, `\`).
   - Enforces strict hostname matching against the contract's `trusted_hosts` allowlist and prevents duplicate artifact URI replay via `consumed_uris`.

2. **Prompt-Injection Isolation & Verbatim Excerpt Grounding (`_excerpt_anchored_in_artifact`)**:
   - Fetched artifacts (bounded between 32 B and 32 KB) are hashed with SHA-256 and evaluated as untrusted text.
   - Any `CONFIRMED` or `REFUTED` verdict must include a contiguous 3–200 character verbatim excerpt verified case-insensitively against whitespace-normalized artifact text. Unanchored quotes deterministically downgrade to `INDETERMINATE` (`LLM_ERROR:UNANCHORED_QUOTE`).

3. **8-Field AdjudicationSeal Equivalence Consensus**:
   - Validators independently fetch the HTTPS artifact and execute LLM evaluation inside `gl.vm.run_nondet_unsafe`, requiring exact 1:1 equality across all 8 `AdjudicationSeal` fields (`vertex_id`, `is_revocation`, `http_code`, `artifact_sha256`, `verdict`, `excerpt`, `audit_code`, `decided_at`).

4. **Selective Cascade Quarantine & Conservation of Funds (`_verify_vault_conservation`)**:
   - Every state transition verifies `cumulative_inflow_wei - cumulative_outflow_wei == vault_unallocated_wei + vault_escrowed_wei + vault_frozen_wei` and `cumulative_outflow_wei == vault_disbursed_wei`.
   - Confirmed revocation of an upstream vertex atomically halts and freezes all reachable downstream dependents while leaving disjoint branches untouched.
