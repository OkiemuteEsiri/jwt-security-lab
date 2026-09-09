# Assessment Methodology

## Scope
This lab assesses JWT validation and authorization policy using synthetic configuration metadata. It does not attack live systems or generate forged tokens.

## Review sequence
1. Confirm algorithm policy is explicit and asymmetric where required.
2. Verify issuer and audience checks are mandatory.
3. Verify `exp` and `iat` handling and bounded token lifetime.
4. Review signing-key rotation expectations and key identifiers.
5. Identify authorization-critical claims and ensure server-side policy remains authoritative.
6. Assign severity based on authentication/authorization impact and control weakness.
7. Record remediation evidence and re-run the policy engine.

## Risk interpretation
Critical findings represent conditions that can materially undermine token trust or authorization boundaries. High findings weaken token acceptance controls. Medium findings reduce resilience, governance, or key lifecycle assurance.

## Evidence
Expected evidence includes secure framework configuration, identity-provider policy, key rotation records, gateway validation rules, automated test output, and change records. No production secrets or token values should be committed to this repository.
