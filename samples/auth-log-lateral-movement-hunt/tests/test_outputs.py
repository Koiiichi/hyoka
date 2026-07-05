from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

OUTPUT_FILE = Path("/root/findings.json")

# Ground truth derived from environment/data/build_inputs.py. Order does not
# matter -- verification is against the set of (host, timestamp) pairs plus
# a lenient technique-prefix check, so re-ordering or extra whitespace in the
# agent's output cannot cause a false failure.
EXPECTED = [
    {"host": "web01", "timestamp": "2026-05-06T02:14:41", "technique_prefix": "T1110"},
    {"host": "app02", "timestamp": "2026-05-06T02:24:07", "technique_prefix": "T1021"},
    {"host": "app02", "timestamp": "2026-05-06T02:31:55", "technique_prefix": "T1548"},
    {"host": "db03", "timestamp": "2026-05-06T02:37:20", "technique_prefix": "T1021"},
    {"host": "db03", "timestamp": "2026-05-06T02:40:44", "technique_prefix": "T1005"},
]

TS_FORMATS = ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"]


def normalize_timestamp(raw: str) -> str:
    raw = raw.strip()
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt).strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            continue
    raise AssertionError(f"Unparseable timestamp in findings.json: {raw!r}")


def load_findings() -> list[dict]:
    assert OUTPUT_FILE.exists(), f"Missing required output: {OUTPUT_FILE}"
    raw = json.loads(OUTPUT_FILE.read_text(encoding="utf-8"))
    assert isinstance(raw, list), "findings.json must be a JSON list of finding objects"
    return raw


class TestAuthLogHunt:
    def test_findings_schema(self):
        """Every finding has the required fields and a normalizable timestamp."""
        findings = load_findings()
        assert findings, "findings.json is empty"
        for f in findings:
            for field in ("host", "timestamp", "mitre_technique"):
                assert field in f, f"Finding missing required field '{field}': {f}"
            normalize_timestamp(f["timestamp"])

    def test_no_excessive_findings(self):
        """A correct answer names exactly the chain; dumping many guesses should not pass."""
        findings = load_findings()
        assert len(findings) <= 8, (
            f"Submitted {len(findings)} findings -- expected a precise chain (5 events), "
            "not a broad sweep of every suspicious-looking line."
        )

    def test_exact_chain_identified(self):
        """The submitted (host, timestamp) set must match the attack chain exactly, no omissions or extras."""
        findings = load_findings()

        submitted = set()
        technique_by_key = {}
        for f in findings:
            host = str(f["host"]).strip().lower()
            norm_ts = normalize_timestamp(str(f["timestamp"]))
            key = (host, norm_ts)
            submitted.add(key)
            technique_by_key[key] = str(f["mitre_technique"]).strip().upper()

        expected_keys = {(e["host"], e["timestamp"]) for e in EXPECTED}

        missing = expected_keys - submitted
        extra = submitted - expected_keys
        assert not missing, f"Missing required chain events: {sorted(missing)}"
        assert not extra, f"Flagged events that are not part of the real chain (false positives): {sorted(extra)}"

        for e in EXPECTED:
            key = (e["host"], e["timestamp"])
            technique = technique_by_key[key]
            assert technique.startswith(e["technique_prefix"]), (
                f"Event {key} should map to a {e['technique_prefix']}* MITRE technique, got {technique!r}"
            )

    def test_decoy_scanner_not_flagged(self):
        """The unrelated background scanner (198.51.100.23, never succeeds) must not appear as a finding."""
        findings = load_findings()
        for f in findings:
            assert "198.51.100.23" not in json.dumps(f), (
                "The background scanner from 198.51.100.23 never achieved a successful login "
                "and should not be reported as a compromise."
            )
