import importlib.util
import pathlib
import unittest

MODULE = pathlib.Path(__file__).parents[1] / "src" / "jwt_review.py"
spec = importlib.util.spec_from_file_location("jwt_review", MODULE)
jwt_review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jwt_review)


class JwtReviewTests(unittest.TestCase):
    def test_secure_config_has_no_findings(self):
        cfg = {"algorithm":"RS256","validate_issuer":True,"validate_audience":True,"require_exp":True,"require_iat":True,"access_token_ttl_minutes":15,"rotation_expected":True,"require_kid":True,"signing_key_age_days":30,"trust_authorization_claims_without_server_policy":False}
        self.assertEqual(jwt_review.review(cfg), [])

    def test_none_algorithm_is_critical(self):
        findings = jwt_review.review({"algorithm":"none"})
        self.assertTrue(any(f.control_id == "JWT-01" and f.severity == "critical" for f in findings))

    def test_missing_audience_is_high(self):
        findings = jwt_review.review({"algorithm":"RS256","validate_issuer":True,"validate_audience":False})
        self.assertTrue(any(f.control_id == "JWT-03" and f.severity == "high" for f in findings))

    def test_excessive_ttl_is_detected(self):
        findings = jwt_review.review({"algorithm":"RS256","access_token_ttl_minutes":60})
        self.assertTrue(any(f.control_id == "JWT-06" for f in findings))

    def test_score_is_capped(self):
        finding = jwt_review.Finding("X", "critical", "x", "y")
        self.assertEqual(jwt_review.score([finding] * 20), 100)


if __name__ == "__main__":
    unittest.main()
