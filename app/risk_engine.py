"""Deterministic, explainable Login Intent Assurance Engine policies."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskPolicy:
    unknown_device: int = 30
    repeated_failures: int = 25
    unusual_context: int = 15
    browser_changed: int = 10
    low_max: int = 24
    medium_max: int = 49
    repeated_failure_threshold: int = 3


@dataclass(frozen=True)
class RiskDecision:
    score: int
    band: str
    action: str
    explanation: str
    signals: tuple[str, ...]
    policy: str


def evaluate_risk(
    *,
    trusted_device: bool,
    recent_failures: int = 0,
    unusual_context: bool = False,
    browser_changed: bool = False,
    qr_valid: bool = True,
    device_revoked: bool = False,
    otp_valid: bool = True,
    policy: RiskPolicy | None = None,
) -> RiskDecision:
    """Score contextual signals without allowing scores to bypass hard checks."""
    policy = policy or RiskPolicy()
    mandatory_failures = []
    if not qr_valid:
        mandatory_failures.append("The QR request is invalid, expired, or already consumed.")
    if device_revoked:
        mandatory_failures.append("The approving device has been revoked.")
    if not otp_valid:
        mandatory_failures.append("The required one-time code was not valid.")
    if mandatory_failures:
        return RiskDecision(
            score=100,
            band="rejected",
            action="reject",
            explanation=" ".join(mandatory_failures),
            signals=tuple(mandatory_failures),
            policy="mandatory_checks",
        )

    score = 0
    signals = []
    if not trusted_device:
        score += policy.unknown_device
        signals.append(f"Unrecognized device (+{policy.unknown_device}).")
    if recent_failures >= policy.repeated_failure_threshold:
        score += policy.repeated_failures
        signals.append(f"Repeated recent authentication failures (+{policy.repeated_failures}).")
    if unusual_context:
        score += policy.unusual_context
        signals.append(f"Unusual authentication context (+{policy.unusual_context}).")
    if browser_changed:
        score += policy.browser_changed
        signals.append(f"Browser characteristics changed (+{policy.browser_changed}).")

    if score <= policy.low_max:
        band, action = "low", "continue"
        explanation = "Risk is low; continue only after all required checks pass."
    elif score <= policy.medium_max:
        band, action = "medium", "require_additional_verification"
        explanation = "Risk is elevated; complete additional verification before access."
    else:
        band, action = "high", "deny"
        explanation = "Risk exceeds the configured high-risk threshold; access is denied."
    if signals:
        explanation = " ".join(signals) + " " + explanation
    else:
        signals.append("No elevated risk signals detected.")
    return RiskDecision(
        score=score,
        band=band,
        action=action,
        explanation=explanation,
        signals=tuple(signals),
        policy="liae_v1",
    )