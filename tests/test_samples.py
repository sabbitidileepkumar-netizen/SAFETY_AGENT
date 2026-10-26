from __future__ import annotations

import json
from pathlib import Path

from app.risk import analyze


SAMPLES = json.loads((Path(__file__).parent / "samples.json").read_text(encoding="utf-8"))


def test_all_30_harmless_labeled_samples_match() -> None:
    mismatches: list[str] = []
    for sample in SAMPLES:
        result = analyze(
            sample["value"] if sample["kind"] == "url" else None,
            sample["value"] if sample["kind"] == "text" else None,
        ).response
        if result.risk != sample["expected"]:
            mismatches.append(f"{sample['id']}: expected {sample['expected']}, got {result.risk}")
    assert not mismatches, "; ".join(mismatches)
