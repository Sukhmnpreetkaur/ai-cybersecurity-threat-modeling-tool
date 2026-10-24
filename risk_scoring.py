"""
Risk Scoring Engine for AI-Assisted Threat Modeling Tool.
Calculates qualitative risk based on Likelihood and Impact matrices (1-5 scale)
and maps scores to industry-standard risk tiers.
"""

from typing import Dict, Any


# Risk level definitions and thresholds
# Low (1–4), Medium (5–9), High (10–16), Critical (17–25)
RISK_LEVEL_THRESHOLDS = {
    "Low": (1, 4),
    "Medium": (5, 9),
    "High": (10, 16),
    "Critical": (17, 25),
}

RISK_LEVEL_COLORS = {
    "Critical": "#FF3366",  # Cyber Red
    "High": "#FF9100",      # Cyber Amber/Orange
    "Medium": "#FFD600",    # Cyber Yellow
    "Low": "#00E676",       # Cyber Neon Green
}

RISK_LEVEL_BADGES = {
    "Critical": "CRITICAL",
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
}


def calculate_risk_score(likelihood: int, impact: int) -> int:
    """
    Calculate the risk score as Likelihood * Impact.
    Both parameters must be integers in the range [1, 5].

    Args:
        likelihood: Integer between 1 (Rare) and 5 (Almost Certain).
        impact: Integer between 1 (Insignificant) and 5 (Catastrophic).

    Returns:
        Risk score integer between 1 and 25.

    Raises:
        TypeError: If likelihood or impact is not an integer.
        ValueError: If likelihood or impact is outside the [1, 5] range.
    """
    if not isinstance(likelihood, int) or not isinstance(impact, int):
        raise TypeError("Likelihood and impact must both be integers.")

    if not (1 <= likelihood <= 5):
        raise ValueError(f"Likelihood must be between 1 and 5, received {likelihood}.")

    if not (1 <= impact <= 5):
        raise ValueError(f"Impact must be between 1 and 5, received {impact}.")

    return likelihood * impact


def get_risk_level(score: int) -> str:
    """
    Determine the qualitative risk classification based on calculated score:
    - Low: 1 - 4
    - Medium: 5 - 9
    - High: 10 - 16
    - Critical: 17 - 25

    Args:
        score: Integer risk score (1 to 25).

    Returns:
        Qualitative tier: 'Low', 'Medium', 'High', or 'Critical'.

    Raises:
        TypeError: If score is not an integer.
        ValueError: If score is outside valid range [1, 25].
    """
    if not isinstance(score, int):
        raise TypeError("Risk score must be an integer.")

    if not (1 <= score <= 25):
        raise ValueError(f"Risk score must be between 1 and 25, received {score}.")

    if score <= 4:
        return "Low"
    elif score <= 9:
        return "Medium"
    elif score <= 16:
        return "High"
    else:
        return "Critical"


def get_risk_metadata(likelihood: int, impact: int) -> Dict[str, Any]:
    """
    Computes score, level, color badge, and formatted display payload.
    """
    score = calculate_risk_score(likelihood, impact)
    level = get_risk_level(score)
    return {
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": score,
        "risk_level": level,
        "color": RISK_LEVEL_COLORS[level],
        "badge": RISK_LEVEL_BADGES[level],
    }
