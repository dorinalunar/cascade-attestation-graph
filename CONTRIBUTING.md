# Contributing to CascadeAttestationGraph

Contributions that enhance DAG invariant verification, URI security, or consensus test vectors are welcome.

## Development Workflow
1. Fork the repository and create a feature branch.
2. Install dependencies via `pip install -r requirements.txt`.
3. Execute the verification test suite locally:
   ```bash
   pytest -v
   ```
4. Ensure all state transitions preserve `_verify_vault_conservation()` and exact 8-field validator consensus equivalence.
5. Submit a Pull Request detailing your changes.
