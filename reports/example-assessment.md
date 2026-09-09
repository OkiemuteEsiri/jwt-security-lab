# Example JWT Security Assessment

## Executive summary
A synthetic legacy API configuration produced multiple authentication and authorization assurance gaps. The highest-risk issues were unsupported algorithm policy and server-side trust of authorization-critical claims without an authoritative policy check.

## Example findings
| ID | Severity | Finding | Recommended action |
|---|---|---|---|
| JWT-01 | Critical | Unsupported algorithm policy | Restrict accepted algorithms to an approved asymmetric allow-list |
| JWT-09 | Critical | Authorization claims implicitly trusted | Enforce server-side authorization policy |
| JWT-02 | High | Issuer validation disabled | Require expected issuer |
| JWT-03 | High | Audience validation disabled | Require expected audience |
| JWT-04 | High | Expiration not required | Require and validate expiration |
| JWT-06 | Medium | Long access-token lifetime | Reduce lifetime and use controlled refresh flow |

## Validation plan
Re-run the policy engine after configuration changes and retain the resulting zero/accepted-risk finding state together with reviewed change evidence. This report is illustrative and contains no real organization data.
