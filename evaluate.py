#!/usr/bin/env python3
"""
evaluate.py
Compare detector alerts in incidents.json against data/ground_truth.json.

The evaluator works primarily at the event level:
  TP = detector-marked attack events that are ground-truth attack events
  FP = detector-marked attack events that are not ground-truth attack events
  FN = ground-truth attack events missed by the detector

It also reports incident/attack coverage when ground_truth has named attacks.

Usage:
    python evaluate.py
    python evaluate.py --detector incidents.json \
        --ground-truth data/ground_truth.json \
        --clean data/clean_logs.csv
"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp", "user", "device", "src_ip",
    "app", "event_type", "target", "geo"
]


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def normalize_incidents(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        if "incidents" in data:
            data = data["incidents"]
        elif "attacks" in data:
            a = data["attacks"]
            data = list(a.values()) if isinstance(a, dict) else a
        else:
            data = [data]
    if not isinstance(data, list):
        return []
    return [x for x in data if isinstance(x, dict)]


def event_signature(event: Dict[str, Any]) -> Tuple[str, ...]:
    """
    Exact event identity. If the detector includes log_index, that is preferred.
    Otherwise use the team's eight log fields.
    """
    if event.get("log_index") is not None:
        return ("index", str(event["log_index"]))

    return tuple(str(event.get(c, "")).strip() for c in REQUIRED_COLUMNS)


def iter_events(obj: Any) -> Iterable[Dict[str, Any]]:
    """Yield event dictionaries from several reasonable JSON layouts."""
    if isinstance(obj, dict):
        for key in ("events", "event_ids", "log_events", "logs"):
            value = obj.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield item
                    elif isinstance(item, (int, str)):
                        yield {"log_index": item}

        # A ground-truth attack may use an 'event_indices' list.
        if isinstance(obj.get("event_indices"), list):
            for item in obj["event_indices"]:
                yield {"log_index": item}

    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                yield item
            elif isinstance(item, (int, str)):
                yield {"log_index": item}


def collect_detector_events(data: Any) -> Set[Tuple[str, ...]]:
    result = set()
    for incident in normalize_incidents(data):
        for event in iter_events(incident):
            result.add(event_signature(event))
    return result


def collect_ground_truth_events(data: Any) -> Tuple[Set[Tuple[str, ...]], Dict[str, Set[Tuple[str, ...]]]]:
    all_events = set()
    by_attack = {}

    attacks = normalize_incidents(data)
    for i, attack in enumerate(attacks, start=1):
        attack_name = str(
            attack.get("attack_id")
            or attack.get("incident_id")
            or attack.get("name")
            or f"attack-{i}"
        )
        events = set()
        for event in iter_events(attack):
            sig = event_signature(event)
            events.add(sig)
            all_events.add(sig)
        if events:
            by_attack[attack_name] = events

    return all_events, by_attack


def clean_alert_count(detector_data: Any, clean_logs: Path) -> int:
    """
    Best-effort clean-log false-alert count.

    If incidents contain log_index values, this counts incidents that reference
    rows present in the clean log. Otherwise, it counts detector incidents with
    events whose exact eight-field signatures occur in clean_logs.

    For a truly clean file, the expected value is 0.
    """
    if not clean_logs.exists():
        return -1

    df = pd.read_csv(clean_logs)
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"{clean_logs} is missing columns: {missing}")

    clean_signatures = {
        tuple(str(row[c]).strip() for c in REQUIRED_COLUMNS)
        for _, row in df.iterrows()
    }

    count = 0
    for incident in normalize_incidents(detector_data):
        matched = False
        for event in iter_events(incident):
            if event_signature(event) in clean_signatures:
                matched = True
                break
        if matched:
            count += 1

    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--detector", default="incidents.json")
    parser.add_argument("--ground-truth", default="data/ground_truth.json")
    parser.add_argument("--clean", default="data/clean_logs.csv")
    args = parser.parse_args()

    detector_path = Path(args.detector)
    truth_path = Path(args.ground_truth)

    if not detector_path.exists():
        print(f"Detector output not found: {detector_path}")
        print("Precision/recall cannot be calculated until incidents.json exists.")
        print("Tip: report.py can still run using its built-in fake incident.")
        return

    if not truth_path.exists():
        print(f"Ground truth not found: {truth_path}")
        print("Precision/recall cannot be calculated until ground_truth.json exists.")
        return

    detector_data = load_json(detector_path)
    truth_data = load_json(truth_path)

    predicted = collect_detector_events(detector_data)
    actual, by_attack = collect_ground_truth_events(truth_data)

    tp = len(predicted & actual)
    fp = len(predicted - actual)
    fn = len(actual - predicted)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    print("=== Detector Evaluation ===")
    print(f"Predicted attack events : {len(predicted)}")
    print(f"Ground-truth events     : {len(actual)}")
    print(f"True positives (TP)     : {tp}")
    print(f"False positives (FP)    : {fp}")
    print(f"False negatives (FN)    : {fn}")
    print(f"Precision               : {precision:.3f}")
    print(f"Recall                  : {recall:.3f}")

    if by_attack:
        covered = sum(bool(events & predicted) for events in by_attack.values())
        print(f"Attacks in ground truth : {len(by_attack)}")
        print(f"Attacks detected        : {covered}/{len(by_attack)}")

    clean_count = clean_alert_count(detector_data, Path(args.clean))
    print()
    print("=== Clean-log check ===")
    if clean_count < 0:
        print(f"Clean log not found: {args.clean}")
    else:
        print(f"Alerts on clean logs    : {clean_count}")
        if clean_count == 0:
            print("PASS: expected 0 alerts on clean logs.")
        else:
            print("FAIL: clean logs produced alerts; investigate false positives.")


if __name__ == "__main__":
    main()
