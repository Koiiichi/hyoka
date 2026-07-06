from __future__ import annotations

import json
import os
from pathlib import Path

TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
OUTPUT_FILE = TASK_ROOT / "findings.json"
GROUND_TRUTH = Path(__file__).parent / "ground_truth.json"

# Perfect identification of the intrusion's malicious events is required for a
# pass. reward.txt records the fractional F1 (see score_reward.py); this defines
# the binary pass@k signal.
PASS_F1 = 0.99


def extract_id(item) -> str:
    if isinstance(item, str):
        return item.strip()
    if isinstance(item, dict):
        for k in ("event_id", "id", "eventid"):
            if k in item:
                return str(item[k]).strip()
    raise AssertionError(f"Cannot extract an event id from finding: {item!r}")


def load_findings():
    assert OUTPUT_FILE.exists(), f"Missing required output: {OUTPUT_FILE}"
    raw = json.loads(OUTPUT_FILE.read_text(encoding="utf-8"))
    assert isinstance(raw, list), "findings.json must be a JSON list of event ids"
    return {extract_id(x) for x in raw}


def load_truth():
    return set(json.loads(GROUND_TRUTH.read_text(encoding="utf-8")))


def score(submitted, truth):
    tp = len(submitted & truth)
    precision = tp / len(submitted) if submitted else 0.0
    recall = tp / len(truth) if truth else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


class TestThreatHunt:
    def test_findings_present(self):
        findings = load_findings()
        assert findings, "findings.json is empty -- no malicious events were flagged"

    def test_identifies_intrusion(self):
        submitted = load_findings()
        truth = load_truth()
        precision, recall, f1 = score(submitted, truth)
        assert f1 >= PASS_F1, (
            f"F1={f1:.3f} (precision={precision:.3f}, recall={recall:.3f}); flagged "
            f"{len(submitted)} events, {len(submitted & truth)} of {len(truth)} malicious. "
            "The intrusion is a cross-source PsExec-style remote execution: a non-machine network "
            "logon (Security 4624 type 3), a stager service installed with an encoded-PowerShell "
            "path (Security 4697 + System 7045), and the service-spawned encoded PowerShell (Sysmon 1); "
            "flag exactly those (over-flagging benign activity destroys precision, and missing the "
            "activity in any one of the three log sources destroys recall)."
        )
