"""Small grading helpers shared by the comparison and evaluation scripts."""

import statistics

# Wording a safe refusal must contain, for each reason: at least one phrase from every group
REFUSAL_WORDS = {
    "unknown product": [["no matching cve", "doesn't cover", "does not cover", "not covered", "isn't covered",
                         "not in callguard", "not a product callguard covers"]],
    "internal data": [["can't see", "cannot see", "can not see", "visibility", "don't have access",
                       "do not have access", "not able to see", "no access", "can't determine", "cannot determine",
                       "can't confirm", "cannot confirm"]],
    "no records": [["no matching cve"], ["not mean", "doesn't mean", "does not mean", "not confirm", "isn't proof",
                                         "not a guarantee", "not guarantee"]],
    "cloud": [["no matching cve"], ["not mean", "doesn't mean", "does not mean"]],
    "out of scope": [["doesn't cover", "does not cover", "not covered", "out of scope"]],
}


def refusal_ok(reason, text):
    """Does a refusal contain the safe wording for its reason?"""
    lower = text.lower().replace("’", "'")  # models often write curly apostrophes: don’t, can’t
    return all(any(phrase in lower for phrase in group) for group in REFUSAL_WORDS[reason])


def p95(values):
    """The time within which 95 of 100 answers arrive."""
    ordered = sorted(values)
    return ordered[round(0.95 * (len(ordered) - 1))]


def summary_times(seconds):
    return f"average {statistics.mean(seconds):.1f} s, p95 {p95(seconds):.1f} s"
