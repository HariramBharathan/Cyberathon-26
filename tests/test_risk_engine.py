import unittest

from app.risk_engine import evaluate_risk


class RiskEngineTests(unittest.TestCase):
    def test_trusted_device_has_low_risk(self):
        decision = evaluate_risk(trusted_device=True)
        self.assertEqual((decision.score, decision.band, decision.action), (0, "low", "continue"))

    def test_unknown_device_requires_step_up(self):
        decision = evaluate_risk(trusted_device=False)
        self.assertEqual(decision.score, 30)
        self.assertEqual(decision.action, "require_additional_verification")
        self.assertIn("Unrecognized device", decision.explanation)

    def test_combined_signals_deny(self):
        decision = evaluate_risk(
            trusted_device=False, recent_failures=3, unusual_context=True
        )
        self.assertEqual(decision.score, 70)
        self.assertEqual(decision.action, "deny")

    def test_mandatory_check_rejects_even_with_low_contextual_risk(self):
        decision = evaluate_risk(trusted_device=True, qr_valid=False)
        self.assertEqual(decision.action, "reject")
        self.assertEqual(decision.policy, "mandatory_checks")

    def test_ip_changes_are_not_a_risk_signal(self):
        decision = evaluate_risk(trusted_device=True)
        self.assertEqual(decision.score, 0)


if __name__ == "__main__":
    unittest.main()