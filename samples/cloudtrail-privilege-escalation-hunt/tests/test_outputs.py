from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

OUTPUT_FILE = Path(os.environ.get("TASK_DATA_ROOT", "/root")) / "findings.json"

# Ground truth derived from environment/data/build_inputs.py. Matching is on the
# set of event_id values (each CloudTrail eventID is globally unique), with a
# lenient MITRE technique-prefix check per event. Re-ordering, extra whitespace,
# or differing timestamp formats in the agent's output cannot cause a false
# failure.
EXPECTED = [
    {"event_id": "a11ac1d0-0001-4a01-8b01-c100000000a1", "technique_prefix": "T1078"},
    {"event_id": "a11ac1d0-0002-4a01-8b01-c100000000a2", "technique_prefix": "T1098"},
    {"event_id": "a11ac1d0-0003-4a01-8b01-c100000000a3", "technique_prefix": "T1530"},
    {"event_id": "a11ac1d0-0004-4a01-8b01-c100000000a4", "technique_prefix": "T1530"},
    {"event_id": "a11ac1d0-0005-4a01-8b01-c100000000a5", "technique_prefix": "T1530"},
    {"event_id": "a11ac1d0-0006-4a01-8b01-c100000000a6", "technique_prefix": "T1530"},
]

# Notable benign look-alikes that resemble a chain step but are not part of it.
DECOY_EVENT_IDS = {
    "dec0de00-0001-4d01-8e01-f00000000d01",  # benign admin CreatePolicyVersion
    "dec0de00-0002-4d01-8e01-f00000000d02",  # benign app read of the PII bucket
    "dec0de00-0003-4d01-8e01-f00000000d03",  # benign high-volume analytics export
    "dec0de00-0004-4d01-8e01-f00000000d04",  # benign quarterly IAM audit read
}

TS_FORMATS = ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]


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


class TestCloudTrailHunt:
    def test_findings_schema(self):
        """Every finding has the required fields and a normalizable timestamp."""
        findings = load_findings()
        assert findings, "findings.json is empty"
        for f in findings:
            for field in ("event_id", "timestamp", "mitre_technique"):
                assert field in f, f"Finding missing required field '{field}': {f}"
            normalize_timestamp(str(f["timestamp"]))

    def test_no_excessive_findings(self):
        """A correct answer names exactly the chain; dumping many guesses should not pass."""
        findings = load_findings()
        assert len(findings) <= 9, (
            f"Submitted {len(findings)} findings -- expected a precise chain (6 events), "
            "not a broad sweep of every suspicious-looking event."
        )

    def test_exact_chain_identified(self):
        """The submitted event_id set must match the attack chain exactly, no omissions or extras."""
        findings = load_findings()

        submitted = set()
        technique_by_id = {}
        for f in findings:
            eid = str(f["event_id"]).strip().lower()
            submitted.add(eid)
            technique_by_id[eid] = str(f["mitre_technique"]).strip().upper()

        expected_ids = {e["event_id"] for e in EXPECTED}

        missing = expected_ids - submitted
        extra = submitted - expected_ids
        assert not missing, f"Missing required chain events: {sorted(missing)}"
        assert not extra, f"Flagged events that are not part of the real chain (false positives): {sorted(extra)}"

        for e in EXPECTED:
            technique = technique_by_id[e["event_id"]]
            assert technique.startswith(e["technique_prefix"]), (
                f"Event {e['event_id']} should map to a {e['technique_prefix']}* MITRE technique, "
                f"got {technique!r}"
            )

    def test_decoys_not_flagged(self):
        """The benign look-alike events (admin edit, app PII read, analytics export, audit) must not appear."""
        findings = load_findings()
        submitted = {str(f["event_id"]).strip().lower() for f in findings}
        flagged_decoys = submitted & DECOY_EVENT_IDS
        assert not flagged_decoys, (
            f"Flagged benign decoy events that are not part of the compromise: {sorted(flagged_decoys)}"
        )
