#!/usr/bin/env python3
"""
report.py
Generate a security incident report for each incident in incidents.json.

Expected log columns:
timestamp, user, device, src_ip, app, event_type, target, geo

Allowed event types:
login, logout, file_access, email_send, usb_mount, bulk_copy, priv_change

Usage:
    python report.py
    python report.py --incidents incidents.json --logs sample_logs.csv --out reports

If incidents.json does not exist, a single fake incident is used so the
reporting pipeline can be developed before the detector is ready.
"""

import argparse
import html
import json
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp", "user", "device", "src_ip",
    "app", "event_type", "target", "geo"
]

ALLOWED_EVENTS = {
    "login", "logout", "file_access", "email_send",
    "usb_mount", "bulk_copy", "priv_change"
}


FAKE_INCIDENT = {
    "incident_id": "FAKE-001",
    "title": "Possible account takeover followed by data theft",
    "events": [
        {
            "timestamp": "2026-03-02 09:01:12",
            "user": "alice",
            "device": "LAP-A1",
            "src_ip": "10.0.1.11",
            "app": "vpn",
            "event_type": "login",
            "target": "-",
            "geo": "IN",
            "stage": "initial_access"
        },
        {
            "timestamp": "2026-03-02 10:15:00",
            "user": "alice",
            "device": "LAP-A1",
            "src_ip": "10.0.1.11",
            "app": "fileserver",
            "event_type": "file_access",
            "target": "/finance/q1_report.xlsx",
            "geo": "IN",
            "stage": "discovery"
        },
        {
            "timestamp": "2026-03-02 10:20:00",
            "user": "alice",
            "device": "LAP-A1",
            "src_ip": "10.0.1.11",
            "app": "fileserver",
            "event_type": "bulk_copy",
            "target": "/finance/q1_report.xlsx",
            "geo": "IN",
            "stage": "data_theft"
        }
    ],
    "stages": ["initial_access", "discovery", "data_theft"],
    "users": ["alice"],
    "score": 78,
    "recommended_actions": [
        "Temporarily disable or step-up authenticate the affected account.",
        "Review recent successful logins and MFA events for the user.",
        "Check the accessed files and preserve relevant audit logs.",
        "Revoke active sessions/tokens if account takeover is confirmed."
    ]
}


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_logs(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=REQUIRED_COLUMNS)

    df = pd.read_csv(path)
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"{path} is missing columns: {missing}")

    # Keep the team's exact column order.
    df = df[REQUIRED_COLUMNS].copy()
    df["_timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def normalize_incidents(data: Any) -> List[Dict[str, Any]]:
    """Accept either a list or {incidents: [...]}."""
    if isinstance(data, dict):
        if "incidents" in data:
            data = data["incidents"]
        else:
            data = [data]

    if not isinstance(data, list):
        return []

    result = []
    for i, incident in enumerate(data, start=1):
        if not isinstance(incident, dict):
            continue
        incident = dict(incident)
        incident.setdefault("incident_id", f"INC-{i:03d}")
        incident.setdefault("events", [])
        result.append(incident)
    return result


def event_from_log_row(row: pd.Series) -> Dict[str, Any]:
    return {c: ("" if pd.isna(row[c]) else row[c]) for c in REQUIRED_COLUMNS}


def find_evidence(incident: Dict[str, Any], logs: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Resolve incident events against the log file.

    Preferred:
      - event contains log_index / row_index
      - event contains an exact timestamp

    Fallback:
      - event fields are matched across all supplied log columns.
    """
    events = incident.get("events", [])
    evidence = []

    for event in events:
        if not isinstance(event, dict):
            continue

        row = None

        for key in ("log_index", "row_index", "index"):
            if key in event:
                try:
                    idx = int(event[key])
                    if 0 <= idx < len(logs):
                        row = logs.iloc[idx]
                        break
                except (TypeError, ValueError):
                    pass

        if row is None and event.get("timestamp"):
            ts = pd.to_datetime(event["timestamp"], errors="coerce")
            if pd.notna(ts):
                candidates = logs[logs["_timestamp"] == ts]
                if len(candidates):
                    # If timestamp is duplicated, use additional fields.
                    for _, candidate in candidates.iterrows():
                        matches = all(
                            str(candidate[c]) == str(event[c])
                            for c in REQUIRED_COLUMNS
                            if c in event and c != "timestamp"
                        )
                        if matches:
                            row = candidate
                            break
                    if row is None:
                        row = candidates.iloc[0]

        if row is None:
            mask = pd.Series(True, index=logs.index)
            matched_any = False
            for c in REQUIRED_COLUMNS:
                if c in event and event[c] not in (None, ""):
                    mask &= logs[c].astype(str).eq(str(event[c]))
                    matched_any = True
            candidates = logs[mask] if matched_any else logs.iloc[0:0]
            if len(candidates):
                row = candidates.iloc[0]

        item = dict(event)
        if row is not None:
            item["evidence"] = event_from_log_row(row)
            item["matched"] = True
        else:
            item["evidence"] = {}
            item["matched"] = False
        evidence.append(item)

    return evidence


def calculate_score(incident: Dict[str, Any], evidence: List[Dict[str, Any]]) -> int:
    """Use detector score if present; otherwise calculate a simple explainable score."""
    supplied = incident.get("score")
    if supplied is not None:
        try:
            return max(0, min(100, int(supplied)))
        except (TypeError, ValueError):
            pass

    events = [e for e in evidence if e.get("matched")]
    types = {e.get("event_type") for e in events}
    score = min(100, len(events) * 10)

    if "priv_change" in types:
        score += 25
    if "bulk_copy" in types:
        score += 20
    if "usb_mount" in types:
        score += 15
    if len({e.get("device") for e in events}) > 1:
        score += 10
    if len({e.get("src_ip") for e in events}) > 1:
        score += 10

    return min(100, score)


def risk_label(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def infer_stages(events: List[Dict[str, Any]]) -> List[str]:
    stages = [e.get("stage") for e in events if e.get("stage")]
    if stages:
        return list(dict.fromkeys(stages))

    mapping = {
        "login": "initial_access",
        "file_access": "discovery",
        "email_send": "collection",
        "usb_mount": "collection",
        "bulk_copy": "data_theft",
        "priv_change": "privilege_escalation",
        "logout": "cleanup"
    }
    return list(dict.fromkeys(mapping.get(e.get("event_type"), "activity") for e in events))


def incident_entities(evidence: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    users, devices, ips = set(), set(), set()
    for event in evidence:
        row = event.get("evidence") or event
        if row.get("user"):
            users.add(str(row["user"]))
        if row.get("device"):
            devices.add(str(row["device"]))
        if row.get("src_ip"):
            ips.add(str(row["src_ip"]))
    return {
        "users": sorted(users),
        "devices": sorted(devices),
        "src_ips": sorted(ips)
    }


def graph_html(incident: Dict[str, Any], evidence: List[Dict[str, Any]], out_file: Path) -> None:
    """
    Build an interactive attack graph with pyvis.
    Falls back to a small HTML message if pyvis is not installed.
    """
    try:
        from pyvis.network import Network
    except ImportError:
        out_file.write_text(
            "<html><body><h2>PyVis is not installed</h2>"
            "<p>Install it with: pip install pyvis</p></body></html>",
            encoding="utf-8"
        )
        return

    net = Network(height="650px", width="100%", directed=True)
    net.set_options("""
    {
      "nodes": {"font": {"size": 16}},
      "edges": {"arrows": {"to": {"enabled": true}}},
      "physics": {"stabilization": true}
    }
    """)

    seen = set()

    def add_node(node_id: str, label: str, shape: str = "dot"):
        if node_id not in seen:
            net.add_node(node_id, label=label, shape=shape)
            seen.add(node_id)

    incident_id = str(incident.get("incident_id", "incident"))
    add_node(incident_id, incident_id, "diamond")

    previous = incident_id
    for i, event in enumerate(evidence, start=1):
        row = event.get("evidence") or event
        event_id = f"{incident_id}-event-{i}"
        label = f"{row.get('event_type', 'event')}\\n{row.get('timestamp', '')}"
        add_node(event_id, label, "box")
        net.add_edge(previous, event_id)
        previous = event_id

        for field, shape in (("user", "ellipse"), ("device", "box"), ("src_ip", "dot")):
            value = row.get(field)
            if value:
                entity_id = f"{field}:{value}"
                add_node(entity_id, f"{field}: {value}", shape)
                net.add_edge(event_id, entity_id)

    net.write_html(str(out_file), open_browser=False)


def render_report(incident: Dict[str, Any], evidence: List[Dict[str, Any]], out_dir: Path) -> Path:
    incident_id = str(incident.get("incident_id", "INC-001"))
    score = calculate_score(incident, evidence)
    label = risk_label(score)
    entities = incident_entities(evidence)
    stages = infer_stages(evidence)

    actions = incident.get("recommended_actions") or [
        "Validate the alert against the underlying log evidence.",
        "Investigate the affected account, devices, and source IPs.",
        "Preserve relevant authentication, file-access, and endpoint logs.",
        "Contain the account/device if malicious activity is confirmed."
    ]

    graph_path = out_dir / f"{incident_id}_attack_graph.html"
    graph_html(incident, evidence, graph_path)

    rows = []
    for i, event in enumerate(evidence, start=1):
        row = event.get("evidence") or event
        proof = " | ".join(f"{c}={row.get(c, '')}" for c in REQUIRED_COLUMNS)
        matched = "YES" if event.get("matched") else "NO"
        rows.append(
            f"<tr><td>{i}</td><td>{html.escape(str(row.get('timestamp', '')))}</td>"
            f"<td>{html.escape(str(event.get('stage', '')))}</td>"
            f"<td>{html.escape(str(row.get('event_type', '')))}</td>"
            f"<td>{html.escape(proof)}</td><td>{matched}</td></tr>"
        )

    users = ", ".join(map(html.escape, entities["users"])) or "—"
    devices = ", ".join(map(html.escape, entities["devices"])) or "—"
    ips = ", ".join(map(html.escape, entities["src_ips"])) or "—"
    stage_text = " → ".join(map(html.escape, stages)) or "—"
    action_html = "".join(f"<li>{html.escape(str(a))}</li>" for a in actions)

    report_path = out_dir / f"{incident_id}_report.html"
    report = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Incident {html.escape(incident_id)}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 32px; line-height: 1.45; }}
.badge {{ display:inline-block; padding:8px 14px; border-radius:8px; font-weight:bold; }}
table {{ border-collapse: collapse; width:100%; font-size:13px; }}
th,td {{ border:1px solid #ccc; padding:7px; vertical-align:top; }}
th {{ background:#eee; }}
code {{ white-space: pre-wrap; }}
.grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; }}
.card {{ border:1px solid #ddd; border-radius:8px; padding:12px; }}
</style>
</head>
<body>
<h1>{html.escape(str(incident.get("title", "Security Incident")))}</h1>
<p><b>Incident:</b> {html.escape(incident_id)}
<span class="badge">{label} — {score}/100</span></p>

<h2>Attack stages</h2>
<p>{stage_text}</p>

<h2>Who / what was involved</h2>
<div class="grid">
<div class="card"><b>Users</b><br>{users}</div>
<div class="card"><b>Devices</b><br>{devices}</div>
<div class="card"><b>Source IPs</b><br>{ips}</div>
</div>

<h2>Timeline and evidence</h2>
<table>
<tr><th>#</th><th>Timestamp</th><th>Stage</th><th>Event</th><th>Log line / proof</th><th>Matched</th></tr>
{''.join(rows)}
</table>

<h2>Recommended actions</h2>
<ul>{action_html}</ul>

<h2>Attack graph</h2>
<p><a href="{html.escape(graph_path.name)}">Open interactive PyVis attack graph</a></p>
<iframe src="{html.escape(graph_path.name)}" width="100%" height="650" style="border:1px solid #ccc;"></iframe>
</body>
</html>"""

    report_path.write_text(report, encoding="utf-8")
    return report_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--incidents", default="incidents.json")
    parser.add_argument("--logs", default="sample_logs.csv")
    parser.add_argument("--out", default="reports")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    logs = load_logs(Path(args.logs))
    incident_data = load_json(Path(args.incidents), {"incidents": [FAKE_INCIDENT]})
    incidents = normalize_incidents(incident_data)

    if not incidents:
        incidents = [FAKE_INCIDENT]

    print(f"Loaded {len(logs)} log rows and {len(incidents)} incident(s).")
    for incident in incidents:
        evidence = find_evidence(incident, logs)
        path = render_report(incident, evidence, out_dir)
        score = calculate_score(incident, evidence)
        print(f"[{incident.get('incident_id')}] {risk_label(score)} {score}/100 -> {path}")


if __name__ == "__main__":
    main()
