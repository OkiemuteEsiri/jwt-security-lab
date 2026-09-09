from __future__ import annotations

import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 1}
ALLOWED_ALGORITHMS = {"RS256", "ES256", "PS256"}


@dataclass(frozen=True)
class Finding:
    control_id: str
    severity: str
    message: str
    remediation: str


def review(config: dict) -> list[Finding]:
    findings: list[Finding] = []
    algorithm = str(config.get("algorithm", "")).upper()

    if algorithm == "NONE" or algorithm not in ALLOWED_ALGORITHMS:
        findings.append(Finding("JWT-01", "critical", f"Algorithm policy allows unsupported value: {algorithm or 'missing'}", "Use an explicit asymmetric algorithm allow-list and reject all other values."))
    if not config.get("validate_issuer", False):
        findings.append(Finding("JWT-02", "high", "Issuer validation is disabled.", "Validate the expected issuer for every accepted token."))
    if not config.get("validate_audience", False):
        findings.append(Finding("JWT-03", "high", "Audience validation is disabled.", "Validate the intended audience/resource server."))
    if not config.get("require_exp", False):
        findings.append(Finding("JWT-04", "high", "Expiration is not required.", "Require and enforce exp with bounded clock skew."))
    if not config.get("require_iat", False):
        findings.append(Finding("JWT-05", "medium", "Issued-at is not required.", "Require iat and reject implausible token age."))
    if int(config.get("access_token_ttl_minutes", 0)) > 30:
        findings.append(Finding("JWT-06", "medium", "Access-token lifetime exceeds 30 minutes.", "Reduce token lifetime according to application risk and refresh-token design."))
    if config.get("rotation_expected", True) and not config.get("require_kid", False):
        findings.append(Finding("JWT-07", "medium", "Key identifier is not required despite key rotation expectations.", "Require deterministic key selection and controlled rotation metadata."))
    if int(config.get("signing_key_age_days", 0)) > 180:
        findings.append(Finding("JWT-08", "medium", "Signing-key age exceeds the lab policy threshold.", "Rotate signing keys using a documented overlap and rollback procedure."))
    if config.get("trust_authorization_claims_without_server_policy", False):
        findings.append(Finding("JWT-09", "critical", "Authorization-critical claims are trusted without server-side policy enforcement.", "Enforce authorization server-side against authoritative policy and validated claims."))
    return findings


def score(findings: list[Finding]) -> int:
    return min(100, sum(SEVERITY_WEIGHT[f.severity] for f in findings))


def main(path: str) -> int:
    records = json.loads(Path(path).read_text(encoding="utf-8"))
    output = []
    for record in records:
        findings = review(record)
        output.append({"name": record.get("name", "unnamed"), "risk_score": score(findings), "findings": [asdict(f) for f in findings]})
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python src/jwt_review.py <config.json>")
    raise SystemExit(main(sys.argv[1]))
