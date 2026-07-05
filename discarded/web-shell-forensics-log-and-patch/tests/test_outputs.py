from __future__ import annotations

import json
import os
import re
from pathlib import Path

TASK_ROOT = Path(os.environ.get("TASK_ROOT", "/root"))
OUTPUT_FILE = TASK_ROOT / "findings.json"

# Ground truth from environment/data/build_inputs.py. Each chain request must be
# reported with a MITRE technique whose family is in the accepted set (a
# sub-technique suffix is fine -- prefix match). The set of request ids must
# match exactly: no missed steps, no decoys. This is ~8 exact inclusions plus 8
# family labels -- many independent decisions, every one of which must be right.
EXPECTED = {
    "c1a10001": {"T1110", "T1078"},          # brute-force success / valid accounts
    "c2b20002": {"T1190", "T1505"},          # exploit upload endpoint / plant web shell
    "c3c30003": {"T1505", "T1190"},          # web shell access
    "c4d40004": {"T1552"},                   # read app credentials file
    "c5e50005": {"T1083", "T1033", "T1087"}, # filesystem discovery
    "c6f60006": {"T1105"},                   # download second-stage tool
    "c7a70007": {"T1560", "T1074"},          # archive collected data
    "c8b80008": {"T1041", "T1567"},          # exfiltrate archive
}

# Decoys that must never be flagged.
DECOY_RIDS = {
    "d1a10001",  # benign admin typo-then-success login
    "d2b20002",  # scanner probing the upload endpoint, never authenticated
    "d3c30003",  # benign feature endpoint that takes a ?cmd= parameter
    "d4d40004",  # legitimate avatar upload
}


def family(technique: str) -> str:
    m = re.match(r"[Tt]\d+", technique.strip())
    return m.group(0).upper() if m else technique.strip().upper()


def load_findings() -> list:
    assert OUTPUT_FILE.exists(), f"Missing required output: {OUTPUT_FILE}"
    raw = json.loads(OUTPUT_FILE.read_text(encoding="utf-8"))
    assert isinstance(raw, list), "findings.json must be a JSON list of finding objects"
    return raw


class TestWebIntrusionHunt:
    def test_schema(self):
        findings = load_findings()
        assert findings, "findings.json is empty"
        for f in findings:
            assert isinstance(f, dict), f"Each finding must be an object: {f!r}"
            assert "request_id" in f, f"Finding missing 'request_id': {f}"
            assert "mitre_technique" in f, f"Finding missing 'mitre_technique': {f}"

    def test_no_excessive_findings(self):
        findings = load_findings()
        assert len(findings) <= 12, (
            f"Submitted {len(findings)} findings -- expected the precise intrusion chain "
            "(8 requests), not a broad sweep of every suspicious-looking request."
        )

    def test_exact_chain_and_techniques(self):
        findings = load_findings()
        by_rid = {str(f["request_id"]).strip(): str(f["mitre_technique"]).strip() for f in findings}
        submitted = set(by_rid)
        expected = set(EXPECTED)

        missing = expected - submitted
        extra = submitted - expected
        assert not missing, f"Missing required chain requests: {sorted(missing)}"
        assert not extra, f"Flagged requests that are not part of the intrusion (false positives): {sorted(extra)}"

        for rid, accepted in EXPECTED.items():
            fam = family(by_rid[rid])
            assert fam in accepted, (
                f"Request {rid} labelled {by_rid[rid]!r} (family {fam}); expected one of "
                f"{sorted(accepted)}. Each step maps to a specific ATT&CK technique family."
            )

    def test_decoys_not_flagged(self):
        findings = load_findings()
        submitted = {str(f["request_id"]).strip() for f in findings}
        overlap = submitted & DECOY_RIDS
        assert not overlap, (
            f"Flagged decoy requests {sorted(overlap)}: these are benign look-alikes (a legitimate "
            "admin login, an unauthenticated scanner, a benign ?cmd= feature, a real avatar upload) "
            "and must not appear in the intrusion chain."
        )
