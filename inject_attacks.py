#!/usr/bin/env python3
"""
Inject three labeled insider/account-takeover attack scenarios into a copy of
clean_logs.csv. If clean_logs.csv is not ready, the script falls back to
sample_logs.csv (including "hacknex sample_logs (2).csv" in Downloads).

Required output:
  data/attack_logs.csv
  data/ground_truth.json

Required CSV columns, in this exact order:
  timestamp,user,device,src_ip,app,event_type,target,geo
"""
from __future__ import annotations

import csv
import json
import random
import ipaddress
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

COLUMNS = ["timestamp", "user", "device", "src_ip", "app", "event_type", "target", "geo"]
ALLOWED_EVENTS = {
    "login", "logout", "file_access", "email_send", "email_read",
    "usb_mount", "bulk_copy", "priv_change"
}
RANDOM_SEED = 20261007
random.seed(RANDOM_SEED)

PROJECT_DIR = Path(__file__).resolve().parent
DATA_DIR = PROJECT_DIR / "data"


def parse_time(value: str) -> datetime:
    """Parse common ISO timestamps, with or without a trailing Z."""
    value = (value or "").strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
                    "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                pass
    raise ValueError(f"Unrecognized timestamp format: {value!r}")


def find_input() -> Path:
    """Prefer Sachin's clean logs; otherwise locate the sample CSV."""
    candidates = [
        DATA_DIR / "clean_logs.csv",
        DATA_DIR / "sample_logs.csv",
        PROJECT_DIR / "clean_logs.csv",
        PROJECT_DIR / "sample_logs.csv",
        Path.home() / "Downloads" / "hacknex sample_logs (2).csv",
        Path.home() / "Downloads" / "sample_logs.csv",
    ]
    for path in candidates:
        if path.is_file():
            return path

    # Support renamed/downloaded sample files in Downloads.
    downloads = Path.home() / "Downloads"
    if downloads.is_dir():
        matches = sorted(downloads.glob("*sample*logs*.csv"))
        if matches:
            return matches[0]

    expected = "\n".join(f"  - {p}" for p in candidates)
    raise FileNotFoundError(
        "Could not find clean_logs.csv or sample_logs.csv.\n"
        "Put Sachin's file at data/clean_logs.csv, or put the sample at "
        "data/sample_logs.csv.\nChecked:\n" + expected
    )


def normalize_rows(input_path: Path) -> tuple[list[dict[str, str]], list[str]]:
    """Read CSV and enforce the required schema without losing source columns."""
    with input_path.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        original = reader.fieldnames or []
        # Strip whitespace from headers, then check exact required names.
        header_map = {name.strip(): name for name in original if name}
        missing = [name for name in COLUMNS if name not in header_map]
        if missing:
            raise ValueError(
                f"{input_path.name} is missing required columns: {missing}\n"
                f"Found columns: {original}\n"
                f"Required order: {COLUMNS}"
            )
        rows = []
        for raw in reader:
            row = {col: (raw.get(header_map[col]) or "").strip() for col in COLUMNS}
            event = row["event_type"].lower()
            if event not in ALLOWED_EVENTS:
                raise ValueError(
                    f"Unsupported event_type {row['event_type']!r}; "
                    f"allowed values are {sorted(ALLOWED_EVENTS)}"
                )
            row["event_type"] = event
            rows.append(row)
    if not rows:
        raise ValueError(f"{input_path} contains a header but no log rows.")
    return rows, COLUMNS


def get_user_history(rows: list[dict[str, str]]):
    histories = defaultdict(list)
    for row in rows:
        histories[row["user"]].append(row)
    return histories


def choose_profile(rows: list[dict[str, str]]):
    """Pick a user with useful history, and infer their usual devices/files/geo."""
    histories = get_user_history(rows)
    eligible = [u for u, rs in histories.items() if u and len(rs) >= 2]
    if not eligible:
        eligible = [u for u in histories if u]
    if not eligible:
        raise ValueError("No non-empty user values found in the input CSV.")

    # Prefer users with file activity and enough history to infer a baseline.
    eligible.sort(
        key=lambda u: (
            sum(r["event_type"] == "file_access" for r in histories[u]),
            len(histories[u]),
        ),
        reverse=True,
    )
    user = eligible[0]
    user_rows = histories[user]
    devices = Counter(r["device"] for r in user_rows if r["device"])
    geos = Counter(r["geo"] for r in user_rows if r["geo"])
    ips = Counter(r["src_ip"] for r in user_rows if r["src_ip"])
    apps = Counter(r["app"] for r in user_rows if r["app"])
    files = Counter(
        r["target"] for r in user_rows
        if r["event_type"] == "file_access" and r["target"]
    )
    usual_devices = list(devices) or ["LAPTOP-NEW"]
    home_geo = geos.most_common(1)[0][0] if geos else "US"
    usual_ip = ips.most_common(1)[0][0] if ips else "192.0.2.10"
    usual_app = apps.most_common(1)[0][0] if apps else "file_server"
    usual_files = list(files)
    all_files = {
        r["target"] for r in rows
        if r["event_type"] == "file_access" and r["target"]
    }
    never_touched = sorted(all_files - set(usual_files))
    # Add plausible synthetic targets if the sample is too small to infer any.
    if not never_touched:
        never_touched = ["Payroll_Q4.xlsx", "Acquisition_Plan.docx", "Customer_Export.csv"]
    return {
        "user": user,
        "device": usual_devices[0],
        "known_devices": set(usual_devices),
        "home_geo": home_geo,
        "usual_ip": usual_ip,
        "app": usual_app,
        "unusual_files": never_touched,
    }


def next_timestamp(rows: list[dict[str, str]]) -> datetime:
    parsed = [parse_time(r["timestamp"]) for r in rows if r["timestamp"]]
    if not parsed:
        return datetime.now().replace(microsecond=0)
    return max(parsed)


def format_like(value: datetime, template: str) -> str:
    """Preserve a common timestamp style from the input."""
    template = (template or "").strip()
    if template.endswith("Z"):
        return value.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    if "T" in template:
        return value.isoformat(timespec="seconds")
    if "/" in template:
        return value.strftime("%m/%d/%Y %H:%M:%S")
    if len(template) == 16:
        return value.strftime("%Y-%m-%d %H:%M")
    return value.strftime("%Y-%m-%d %H:%M:%S")


def synthetic_ip() -> str:
    """Return a documentation-only IP address, not a real external address."""
    return random.choice(["198.51.100.24", "203.0.113.42", "198.51.100.77"])


def make_event(ts, user, device, ip, app, event_type, target, geo, template):
    if event_type not in ALLOWED_EVENTS:
        raise ValueError(f"Invalid event name: {event_type}")
    return {
        "timestamp": format_like(ts, template),
        "user": user,
        "device": device,
        "src_ip": ip,
        "app": app,
        "event_type": event_type,
        "target": target,
        "geo": geo,
    }


def inject(rows: list[dict[str, str]], columns: list[str]):
    profile = choose_profile(rows)
    base = next_timestamp(rows)
    template = rows[0]["timestamp"]
    user = profile["user"]
    device = profile["device"]
    app = profile["app"]
    foreign_geo = "RU" if profile["home_geo"].upper() not in {"RU", "RUSSIA"} else "BR"
    foreign_ip = synthetic_ip()
    suspicious_files = profile["unusual_files"]
    added: list[dict[str, str]] = []
    attacks = {}

    def add(attack_id, description, event_specs):
        events = []
        for offset, dev, ip, event_type, target, geo in event_specs:
            event = make_event(
                base + offset, user, dev, ip, app, event_type, target, geo, template
            )
            added.append(event)
            events.append(event.copy())
        attacks[attack_id] = {
            "description": description,
            "user": user,
            "event_count": len(events),
            "events": events,
        }

    # Attack 1: foreign login, never-before-seen files, USB mount and bulk copy.
    add("attack_1_account_takeover_data_theft",
        "Account takeover: foreign-country login, unusual file access, USB mount, bulk copy.",
        [
            (timedelta(minutes=1), device, foreign_ip, "login", "successful_login", foreign_geo),
            (timedelta(minutes=3), device, foreign_ip, "file_access", suspicious_files[0], foreign_geo),
            (timedelta(minutes=5), device, foreign_ip, "file_access", suspicious_files[min(1, len(suspicious_files)-1)], foreign_geo),
            (timedelta(minutes=7), device, foreign_ip, "usb_mount", "USB-EXTERNAL-01", foreign_geo),
            (timedelta(minutes=9), device, foreign_ip, "bulk_copy", "USB-EXTERNAL-01", foreign_geo),
        ])

    # Attack 2: one identity appears on multiple new devices within minutes,
    # followed by a privilege change.
    new_devices = ["WS-NEW-041", "WS-NEW-042", "WS-NEW-043"]
    add("attack_2_lateral_movement_privilege_change",
        "One user authenticates on several previously unseen devices within minutes, then privilege changes.",
        [
            (timedelta(minutes=20), new_devices[0], synthetic_ip(), "login", "successful_login", profile["home_geo"]),
            (timedelta(minutes=22), new_devices[1], synthetic_ip(), "login", "successful_login", profile["home_geo"]),
            (timedelta(minutes=24), new_devices[2], synthetic_ip(), "login", "successful_login", profile["home_geo"]),
            (timedelta(minutes=27), new_devices[2], synthetic_ip(), "priv_change", "role=administrator", profile["home_geo"]),
        ])

    # Attack 3: same account-takeover/data-theft pattern, but spread across 5 days.
    slow_start = base + timedelta(days=1)
    # Build directly so offsets are measured from the slow-start point.
    slow_specs = [
        (timedelta(minutes=2), device, foreign_ip, "login", "successful_login", foreign_geo),
        (timedelta(days=1, hours=3), device, foreign_ip, "file_access", suspicious_files[0], foreign_geo),
        (timedelta(days=2, hours=5), device, foreign_ip, "file_access", suspicious_files[min(1, len(suspicious_files)-1)], foreign_geo),
        (timedelta(days=3, hours=4), device, foreign_ip, "usb_mount", "USB-EXTERNAL-02", foreign_geo),
        (timedelta(days=4, hours=2), device, foreign_ip, "bulk_copy", "USB-EXTERNAL-02", foreign_geo),
    ]
    slow_events = []
    for offset, dev, ip, event_type, target, geo in slow_specs:
        event = make_event(slow_start + offset, user, dev, ip, app, event_type, target, geo, template)
        added.append(event)
        slow_events.append(event.copy())
    attacks["attack_3_slow_account_takeover_data_theft"] = {
        "description": "Slow account takeover/data theft over five days: foreign login, unusual file access, USB mount, bulk copy.",
        "user": user,
        "event_count": len(slow_events),
        "events": slow_events,
    }

    # Keep original rows intact, then sort all rows chronologically.
    combined = [dict(r) for r in rows] + added
    combined.sort(key=lambda r: parse_time(r["timestamp"]))
    # Use exact required column order; only these eight fields are written.
    return combined, attacks, profile


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    input_path = find_input()
    rows, columns = normalize_rows(input_path)
    combined, attacks, profile = inject(rows, columns)

    output_csv = DATA_DIR / "attack_logs.csv"
    output_json = DATA_DIR / "ground_truth.json"
    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(combined)

    ground_truth = {
        "source_file": str(input_path),
        "output_file": str(output_csv),
        "schema": COLUMNS,
        "attack_event_count": sum(a["event_count"] for a in attacks.values()),
        "attacks": attacks,
        "notes": [
            "Ground truth lists the exact injected event rows under each attack.",
            "Synthetic source IPs are reserved documentation addresses.",
            "The selected user and inferred file targets are derived from the input logs where possible.",
            "This is a labeled test dataset; do not use these synthetic events as real incident evidence."
        ],
    }
    with output_json.open("w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)

    # Validate output structure and event labels before reporting success.
    with output_csv.open("r", newline="", encoding="utf-8-sig") as f:
        check = csv.DictReader(f)
        assert check.fieldnames == COLUMNS, f"Wrong output columns: {check.fieldnames}"
        output_rows = list(check)
    assert len(output_rows) == len(rows) + 14, (
        f"Expected {len(rows) + 14} rows (14 injected), got {len(output_rows)}"
    )
    assert all(r["event_type"] in ALLOWED_EVENTS for r in output_rows)

    print(f"Input: {input_path}")
    print(f"Selected test user: {profile['user']}")
    print(f"Original rows: {len(rows)}")
    print(f"Injected attack events: {sum(a['event_count'] for a in attacks.values())}")
    print(f"Total output rows: {len(output_rows)}")
    print(f"Saved: {output_csv}")
    print(f"Saved: {output_json}")


if __name__ == "__main__":
    main()
