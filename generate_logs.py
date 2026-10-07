#!/usr/bin/env python3
"""generate_logs.py - generate fully clean (benign) enterprise logs.

Output: data/clean_logs.csv
Columns: timestamp,user,device,src_ip,app,event_type,target,geo

Each user gets a fixed profile:
  - home country (geo never changes)
  - department and the usual working hours
  - 1-2 devices, each with a fixed source IP
  - a few files they usually open (only those are ever accessed)

No attacks, no off-hours activity, no foreign logins, no USB/bulk copies.

Usage:
    python generate_logs.py [--users 200] [--days 14] [--start 2026-03-02] [--seed 42]
"""
import argparse
import csv
import os
import random
from datetime import datetime, timedelta

FIRST_NAMES = [
    "alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi", "ivan", "judy",
    "karan", "leela", "manoj", "nisha", "omar", "priya", "quinn", "rahul", "sana", "tarun",
    "uma", "vikram", "waleed", "xena", "yash", "zoya", "arjun", "bhavna", "chetan", "divya",
    "esha", "farhan", "gita", "harsh", "indu", "jatin", "kavya", "lokesh", "meena", "naveen",
    "olivia", "pranav", "ritu", "suresh", "tina", "varun", "wendy", "yusuf", "zara", "anil",
]

# (geo code, weight, ip second octet) - mostly India, some others
COUNTRIES = [("IN", 70, 0), ("US", 10, 1), ("GB", 6, 2), ("DE", 5, 3), ("SG", 5, 4), ("AU", 4, 5)]

DEPARTMENTS = {
    "hr": ["policies.pdf", "handbook.pdf", "leave_tracker.xlsx", "onboarding.docx", "org_chart.pdf",
           "holiday_calendar.pdf", "training_plan.xlsx", "benefits_overview.pdf"],
    "finance": ["q1_report.xlsx", "budget_2026.xlsx", "invoices_march.xlsx", "expense_policy.pdf",
                "vendor_list.xlsx", "forecast.xlsx", "tax_notes.docx", "ledger_summary.xlsx"],
    "sales": ["leads.csv", "pipeline.xlsx", "pricing_sheet.xlsx", "client_list.csv",
              "proposal_template.docx", "quarterly_targets.xlsx", "crm_export.csv", "playbook.pdf"],
    "engineering": ["architecture.pdf", "release_notes.md", "sprint_plan.xlsx", "runbook.md",
                    "api_spec.yaml", "test_report.pdf", "roadmap.pptx", "design_doc.docx"],
    "it": ["asset_inventory.xlsx", "patch_schedule.xlsx", "network_diagram.pdf", "helpdesk_report.csv",
           "backup_policy.pdf", "software_licenses.xlsx", "onboarding_checklist.docx"],
    "marketing": ["campaign_plan.pptx", "brand_guide.pdf", "social_calendar.xlsx", "web_traffic.csv",
                  "press_kit.pdf", "newsletter_draft.docx", "budget_marketing.xlsx"],
    "operations": ["shift_roster.xlsx", "inventory.csv", "vendor_contracts.pdf", "sla_report.xlsx",
                   "process_manual.pdf", "incident_log.csv", "capacity_plan.xlsx"],
}
COMMON_FILES = ["/common/company_news.pdf", "/common/holiday_calendar.pdf", "/common/it_guidelines.pdf"]

DEVICE_PREFIX = {"laptop": "LAP", "desktop": "DSK"}


def build_users(n, rng):
    users = []
    used = {}
    countries = [c for c in COUNTRIES]
    weights = [c[1] for c in COUNTRIES]
    dept_names = list(DEPARTMENTS)
    for i in range(n):
        base = FIRST_NAMES[i % len(FIRST_NAMES)]
        used[base] = used.get(base, 0) + 1
        name = base if used[base] == 1 else f"{base}{used[base]}"

        geo, _, octet = rng.choices(countries, weights=weights, k=1)[0]
        dept = rng.choice(dept_names)

        # usual working hours: start 8:00-10:30, length 8-9h
        start_min = rng.choice(range(8 * 60, 10 * 60 + 31, 15))
        length_min = rng.choice([8 * 60, 8 * 60 + 30, 9 * 60])

        # 1-2 devices, each with a fixed IP
        kinds = ["laptop"] if rng.random() < 0.6 else ["laptop", "desktop"]
        devices = []
        for kind in kinds:
            dev = f"{DEVICE_PREFIX[kind]}-{i + 1:03d}"
            ip = f"10.{octet}.{rng.randint(1, 60)}.{rng.randint(2, 250)}"
            devices.append((dev, ip))

        files = [f"/{dept}/{f}" for f in rng.sample(DEPARTMENTS[dept], rng.randint(3, 5))]
        if rng.random() < 0.25:
            files.append(rng.choice(COMMON_FILES))

        users.append({
            "user": name, "geo": geo, "dept": dept,
            "start_min": start_min, "length_min": length_min,
            "devices": devices, "files": files,
            "activity": rng.uniform(0.6, 1.5),  # how busy this user is
            "email_rate": rng.uniform(0.3, 1.6),
        })
    return users


def gen_day(u, day, rng):
    """Events for one user on one working day."""
    rows = []
    # mostly the primary device; second device sometimes
    if len(u["devices"]) == 2 and rng.random() < 0.3:
        dev, ip = u["devices"][1]
    else:
        dev, ip = u["devices"][0]

    base = datetime(day.year, day.month, day.day)
    login_t = base + timedelta(minutes=u["start_min"] + rng.randint(-12, 25), seconds=rng.randint(0, 59))
    logout_t = base + timedelta(minutes=u["start_min"] + u["length_min"] + rng.randint(-20, 25),
                                seconds=rng.randint(0, 59))

    def row(ts, app, ev, target="-"):
        rows.append((ts, u["user"], dev, ip, app, ev, target, u["geo"]))

    row(login_t, "vpn", "login")

    span = int((logout_t - login_t).total_seconds())
    lo, hi = 600, max(700, span - 600)  # keep activity inside the session

    def rand_ts():
        return login_t + timedelta(seconds=rng.randint(lo, hi))

    n_files = max(1, int(rng.gauss(5, 2) * u["activity"]))
    for _ in range(n_files):
        row(rand_ts(), "fileserver", "file_access", rng.choice(u["files"]))

    n_sent = int(rng.gauss(4, 2) * u["email_rate"])
    for _ in range(max(0, n_sent)):
        row(rand_ts(), "email", "email_send")
    n_read = int(rng.gauss(6, 2) * u["email_rate"])
    for _ in range(max(0, n_read)):
        row(rand_ts(), "email", "email_read")

    row(logout_t, "vpn", "logout")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--users", type=int, default=200)
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--start", default="2026-03-02")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data/clean_logs.csv")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    users = build_users(args.users, rng)
    start = datetime.strptime(args.start, "%Y-%m-%d")

    all_rows = []
    for d in range(args.days):
        day = start + timedelta(days=d)
        if day.weekday() >= 5:  # normal behaviour: no weekend work
            continue
        for u in users:
            if rng.random() < 0.04:  # occasional leave / absence
                continue
            all_rows.extend(gen_day(u, day, rng))

    all_rows.sort(key=lambda r: (r[0], r[1]))

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "user", "device", "src_ip", "app", "event_type", "target", "geo"])
        for ts, user, dev, ip, app, ev, target, geo in all_rows:
            w.writerow([ts.strftime("%Y-%m-%d %H:%M:%S"), user, dev, ip, app, ev, target, geo])

    print(f"Wrote {len(all_rows)} events for {len(users)} users to {args.out}")


if __name__ == "__main__":
    main()
