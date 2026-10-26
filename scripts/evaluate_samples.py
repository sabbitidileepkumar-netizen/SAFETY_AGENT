from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))

from app.risk import analyze


ORDER = {"Safe": 0, "Careful": 1, "Danger": 2}


def main() -> None:
    samples_path = ROOT / "tests" / "samples.json"
    samples = json.loads(samples_path.read_text(encoding="utf-8"))
    correct = 0
    false_positives = 0
    false_negatives = 0
    for sample in samples:
        result = analyze(
            sample["value"] if sample["kind"] == "url" else None,
            sample["value"] if sample["kind"] == "text" else None,
        ).response
        expected = sample["expected"]
        if result.risk == expected:
            correct += 1
        elif ORDER[result.risk] > ORDER[expected]:
            false_positives += 1
        else:
            false_negatives += 1
    total = len(samples)
    print(f"samples: {total}")
    print(f"accuracy: {correct / total:.2%}")
    print(f"false positives (over-warnings): {false_positives}")
    print(f"false negatives (under-warnings): {false_negatives}")


if __name__ == "__main__":
    main()
