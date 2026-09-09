# JWT Security Review Lab

Defensive Web/API security engineering project for reviewing JSON Web Token configurations, claims, validation policy, and authorization assumptions using **synthetic lab data only**.

## Problem statement
JWT failures are often caused by implementation and configuration mistakes rather than cryptography itself: weak algorithm policy, missing issuer/audience validation, excessive token lifetime, unsafe claim trust, missing rotation metadata, and authorization decisions based on unverified client-controlled context. This project converts those risks into repeatable policy checks and remediation evidence.

## Architecture

```text
Synthetic token metadata
        |
        v
src/jwt_review.py
  - policy checks
  - severity classification
  - risk scoring
        |
        +--> findings.json-style output
        +--> remediation guidance
        +--> validation evidence
```

## Controls implemented
- Reject `alg=none` and algorithms outside an explicit allow-list.
- Require issuer and audience validation.
- Flag excessive access-token lifetime.
- Require expiration and issued-at claims.
- Detect missing key identifiers where rotation is expected.
- Flag authorization-critical claims that are configured as implicitly trusted.
- Require documented signing-key rotation age.

## Risk model
Each finding is assigned a severity and weighted score. The lab intentionally evaluates **configuration metadata**, not live tokens or production endpoints.

| Severity | Weight |
|---|---:|
| Critical | 10 |
| High | 7 |
| Medium | 4 |
| Low | 1 |

## Repository structure
- `src/jwt_review.py` — defensive policy engine.
- `data/synthetic_jwt_configs.json` — non-functional synthetic configurations.
- `tests/test_jwt_review.py` — unit tests.
- `docs/methodology.md` — assessment method and security rationale.
- `docs/remediation-validation.md` — fix and re-test workflow.
- `reports/example-assessment.md` — recruiter-readable example report.
- `.github/workflows/tests.yml` — CI unit-test workflow.

## Usage

```bash
python -m unittest discover -s tests -v
python src/jwt_review.py data/synthetic_jwt_configs.json
```

## MITRE ATT&CK context
JWT weaknesses can enable or amplify **Valid Accounts (T1078)** when stolen or improperly validated tokens are accepted. The project maps this only as defensive context; it contains no token theft, forgery, bypass, or exploit automation.

## Skills demonstrated
Web/API security engineering, authentication design review, authorization assurance, policy-as-code, Python, unit testing, risk communication, remediation validation, and CI/CD security checks.

## Limitations
This is not a penetration-testing exploit kit. It does not attack live applications, generate forged tokens, brute-force secrets, or validate production credentials. Real-world assurance also requires framework-specific code review, gateway configuration review, key-management review, and authorized runtime testing.

## Roadmap
- Add OpenID Connect discovery-policy checks.
- Add JWKS cache/rotation validation fixtures.
- Add machine-readable control identifiers and SARIF-style output.
- Add framework-specific secure configuration examples.
