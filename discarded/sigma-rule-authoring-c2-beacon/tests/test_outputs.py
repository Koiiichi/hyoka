from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import sigma_verifier  # noqa: E402

try:
    import yaml
except ImportError:
    yaml = None

TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
RULE_FILE = TASK_ROOT / "sigma_rule.yml"

# Perfect generalization on the held-out network is required for a pass. The
# reward written to reward.txt is the fractional F1 (see score_reward.py); this
# threshold defines the binary pass@k signal.
PASS_F1 = 0.999


def load_rule():
    assert RULE_FILE.exists(), f"Missing required output: {RULE_FILE}"
    assert yaml is not None, "PyYAML not available in verifier"
    text = RULE_FILE.read_text(encoding="utf-8")
    try:
        rule = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise AssertionError(f"sigma_rule.yml is not valid YAML: {exc}")
    assert isinstance(rule, dict), "sigma_rule.yml must parse to a mapping"
    return rule


class TestSigmaRule:
    def test_structural_validity(self):
        """Valid Sigma shape, proxy logsource, and no banned destination field."""
        rule = load_rule()
        ok, reason = sigma_verifier.validate(rule)
        assert ok, f"Rule failed structural validation: {reason}"

    def test_does_not_reference_destination(self):
        """A rule keyed on the C2 domain/IP cannot generalize and is disallowed."""
        rule = load_rule()
        detection = rule.get("detection", {})
        for name, block in detection.items():
            if name == "condition" or not isinstance(block, dict):
                continue
            for key in block:
                assert key.split("|")[0].strip().lower() not in sigma_verifier.BANNED_FIELDS, (
                    f"Rule references destination field '{key}' -- the beacon rotates C2 "
                    "infrastructure, so destination-based rules do not generalize and score 0."
                )

    def test_generalizes_to_heldout(self):
        """Precision and recall must be perfect on the held-out network."""
        rule = load_rule()
        result = sigma_verifier.score(rule)
        assert result["valid"], f"Invalid rule: {result['reason']}"
        assert result["f1"] >= PASS_F1, (
            f"F1={result['f1']:.3f} on the held-out set (precision={result['precision']:.3f}, "
            f"recall={result['recall']:.3f}, tp={result.get('tp')}, fp={result.get('fp')}, "
            f"fn={result.get('fn')}). A single-field or domain-anchored rule cannot reach 1.0: "
            "the held-out network has beacon variants on new domains plus look-alikes that share "
            "one behavioral field. Capture the behavioral intersection that generalizes."
        )
