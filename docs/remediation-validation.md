# Remediation and Validation

## Remediation priorities
1. Enforce an explicit signing-algorithm allow-list and reject `none` or unexpected algorithms.
2. Require issuer, audience, expiration, and issued-at validation.
3. Reduce access-token lifetime according to application risk.
4. Use managed signing-key rotation with deterministic key selection.
5. Keep authorization decisions server-side and tied to validated, authoritative claims.

## Validation evidence
A finding should be closed only when both configuration evidence and repeatable validation exist. Evidence may include a reviewed configuration diff, automated unit/integration tests, gateway or middleware policy output, identity-provider settings, and successful re-execution of this lab's policy checks.

## Closure criteria
- The control no longer produces a finding.
- The fix has a documented owner and implementation date.
- Regression testing covers the corrected behavior.
- No sensitive tokens, secrets, or production identifiers are stored as evidence.
