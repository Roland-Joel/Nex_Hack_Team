import sys
import pandas as pd
import json
from datetime import timedelta

WINDOW = timedelta(hours=72)  # flagged events closer than this get linked (long enough for slow-and-low)
STAGE_ORDER = ["initial_access", "privilege_escalation", "lateral_movement", "collection", "exfiltration"]

ACTIONS = {
    "initial_access": "Force password reset and revoke active sessions for {user}",
    "lateral_movement": "Isolate the new devices {user} logged into",
    "privilege_escalation": "Review and roll back privilege changes for {user}",
    "collection": "Audit files accessed by {user} and block removable media",
    "exfiltration": "Check what was copied, treat that data as leaked, escalate to security team",
}
BASELINE_END = "2026-03-04"  # events before this date define "normal" (for real data, use the first ~7 days)
USB_EVENTS = {"usb_mount", "bulk_copy"}

def load(path):
    df = pd.read_csv(path, parse_dates=["timestamp"])
    df["hour"] = df["timestamp"].dt.hour
    return df.sort_values("timestamp").reset_index(drop=True)

def build_baselines(df):
    base = df[df["timestamp"] < BASELINE_END]
    baselines = {}
    for user, g in base.groupby("user"):
        baselines[user] = {
            "geos": set(g["geo"]),
            "devices": set(g["device"]),
            "files": set(g[g["event_type"] == "file_access"]["target"]),
            "min_hour": g["hour"].min() - 1,
            "max_hour": g["hour"].max() + 1,
        }
    return baselines

def flag_events(df, baselines):
    flagged = []
    for _, r in df.iterrows():
        b = baselines.get(r["user"])
        reasons = []
        if b is None:
            reasons.append("unknown user")
        else:
            if r["geo"] not in b["geos"]:
                reasons.append(f"new country ({r['geo']})")
            if r["device"] not in b["devices"]:
                reasons.append(f"new device ({r['device']})")
            if not (b["min_hour"] <= r["hour"] <= b["max_hour"]):
                reasons.append(f"off-hours ({r['hour']}:00)")
            if r["event_type"] == "file_access" and r["target"] not in b["files"]:
                reasons.append(f"first-time file ({r['target']})")
        if r["event_type"] in USB_EVENTS:
            reasons.append(f"USB activity ({r['event_type']})")
        if reasons:
            flagged.append({**r.to_dict(), "reasons": reasons})
    return flagged

def group_events(flagged):
    """Link flagged events of the same user that are within WINDOW of each other."""
    groups, last = [], {}
    for ev in flagged:
        u = ev["user"]
        if u in last and ev["timestamp"] - last[u]["end"] <= WINDOW:
            last[u]["events"].append(ev)
            last[u]["end"] = ev["timestamp"]
        else:
            g = {"user": u, "events": [ev], "end": ev["timestamp"]}
            groups.append(g)
            last[u] = g
    return groups

def tag_stages(events):
    seen_login = False
    for ev in events:
        et = ev["event_type"]
        if et == "bulk_copy":
            ev["stage"] = "exfiltration"
        elif et in ("usb_mount", "file_access"):
            ev["stage"] = "collection"
        elif et == "priv_change":
            ev["stage"] = "privilege_escalation"
        elif et == "login":
            ev["stage"] = "lateral_movement" if seen_login else "initial_access"
            seen_login = True
        else:
            ev["stage"] = "unknown"

def to_incident(i, g):
    evs = g["events"]
    tag_stages(evs)
    stages = []
    for e in evs:
        if e["stage"] != "unknown" and e["stage"] not in stages:
            stages.append(e["stage"])
    idx = [STAGE_ORDER.index(s) for s in stages]
    in_order = idx == sorted(idx)
    if len(stages) < 2 or not in_order:   # the alert gate
        return None
    risk = min(100, len(stages) * 20 + sum(len(e["reasons"]) for e in evs))
    return {
        "incident_id": f"INC-{i:03d}",
        "user": g["user"],
        "start": str(evs[0]["timestamp"]),
        "end": str(evs[-1]["timestamp"]),
        "stages": stages,
        "devices": sorted({e["device"] for e in evs}),
        "ips": sorted({e["src_ip"] for e in evs}),
        "risk_score": risk,
        "events": [{"timestamp": str(e["timestamp"]), "event_type": e["event_type"],
                    "target": e["target"], "stage": e["stage"], "reasons": e["reasons"]} for e in evs],
        "recommended_actions": [ACTIONS[s].format(user=g["user"]) for s in stages],
    }

def detect(path):
    df = load(path)
    flagged = flag_events(df, build_baselines(df))
    incidents = []
    for g in group_events(flagged):
        inc = to_incident(len(incidents) + 1, g)
        if inc:
            incidents.append(inc)
    return incidents

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/sample_logs.csv"
    incidents = detect(path)
    with open("outputs/incidents.json", "w") as f:
        json.dump(incidents, f, indent=2)
    for inc in incidents:
        print(f"{inc['incident_id']} user={inc['user']} risk={inc['risk_score']} stages={' > '.join(inc['stages'])}")
    print(f"\n{len(incidents)} incident(s) raised")