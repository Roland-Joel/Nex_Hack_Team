# HackNex Attack Chain Detector
 
A small system that finds hackers by connecting tiny suspicious events in computer logs.
 
Any one event (a login from a new country, a file nobody opens, a USB stick) can look harmless. Put several of them together in a sensible order and they tell the story of an attack. This project learns what is normal for each user, flags what breaks that pattern, links the flags together, and raises an alert only when the linked events form a multi-stage attack.
 
## How it works (in plain words)
 
Think of a security guard who knows every employee's habits.
 
1. **Learn normal.** From the first week of logs, remember each user's usual countries, devices, working hours and files.
2. **Flag oddities.** Mark any later event that breaks those habits: a new country, a new device, off-hours activity, a file never opened before, or any USB activity.
3. **Link the flags.** Join flagged events that share a user, device or IP address and happen within 72 hours of each other.
4. **Label the stage.** Give each event a place in the attack story:
   | Event | Stage |
   |---|---|
   | first login in the group | initial_access |
   | later logins | lateral_movement |
   | priv_change | privilege_escalation |
   | file_access, usb_mount | collection |
   | bulk_copy | exfiltration |
5. **Decide whether to alert.** Raise an incident only if all three are true:
   - at least 2 different stages appear,
   - the stages move forward at least once (for example collection, then exfiltration),
   - at least one *strong* signal is present: new country, off-hours, USB activity or a privilege change.
   A new device or a first-time file alone is too common to count as evidence. This rule is what keeps false alarms at zero on clean data.
6. **Report.** Produce a timeline, evidence for each event, a risk score (0-100), recommended actions and an attack graph.
## Team and files
 
| Person | Part | File |
|---|---|---|
| Sachin | Generates fake normal logs | `generate_logs.py` |
| Nithees | Injects fake attacks and writes the answer key | `inject_attacks.py` |
| Roland | Detector | `detect.py` |
| Tharun | Report and accuracy check | `report.py`, `evaluate.py` |
 
Folders:
 
- `data/` holds the log files and the answer key (`clean_logs.csv`, `attack_logs.csv`, `ground_truth.json`).
- `outputs/` holds the detector results and the HTML reports.
## Log format
 
Every log row has these 8 columns, in this order:
 
`timestamp, user, device, src_ip, app, event_type, target, geo`
 
Timestamps look like `2026-03-13 19:42:16`.
 
Event types: `login`, `logout`, `file_access`, `email_send`, `usb_mount`, `bulk_copy`, `priv_change`. Sachin's generator also writes `email_read`. The detector ignores it.
 
## Setup
 
```
pip install pandas pyvis
```
 
`pyvis` is only needed for the attack graph. Everything else works without it.
 
## How to run
 
Run these from the project folder, in order.
 
```
python generate_logs.py
python inject_attacks.py
python detect.py data/attack_logs.csv outputs/incidents_attack.json
python evaluate.py --detector outputs/incidents_attack.json
python report.py --incidents outputs/incidents_attack.json --logs data/attack_logs.csv --out outputs/reports
```
 
What each step does:
 
1. `generate_logs.py` creates `data/clean_logs.csv`: 28,501 normal events for 200 users over two weeks.
2. `inject_attacks.py` copies the clean logs, hides 3 attacks (14 events) in them, and writes `data/attack_logs.csv` plus `data/ground_truth.json` (the answer key).
3. `detect.py` finds incidents and saves them as JSON.
4. `evaluate.py` compares the detector's answers with the answer key and prints precision and recall.
5. `report.py` builds one HTML report per incident in `outputs/reports/`. Open `INC-001_report.html` in a browser.
### Check for false alarms
 
The detector should stay silent on clean data:
 
```
python detect.py data/clean_logs.csv outputs/incidents_clean.json
python evaluate.py --detector outputs/incidents_clean.json
```
 
For this run, ignore the recall numbers (the clean file has no attacks to find). Look only at the "Clean-log check" section, which should say `PASS`.
 
### Using a different baseline period
 
The baseline is the part of the log used to learn "normal". It defaults to everything before `2026-03-09`. To change it, pass a date as the third argument:
 
```
python detect.py data/sample_logs.csv outputs/incidents.json 2026-03-04
```
 
## The three test attacks
 
1. **Account takeover and data theft.** Login from a foreign country, files never opened before, USB mount, bulk copy.
2. **Lateral movement and privilege change.** Logins on three brand-new devices within minutes, then an admin role is granted.
3. **Slow and low.** The same takeover pattern as attack 1, spread over five days to dodge short time windows. The 72-hour linking window is long enough to catch it.
## Results
 
| Test | Result |
|---|---|
| Attack logs, events caught | 14 of 14 |
| Attack logs, false positives | 0 |
| Precision / recall | 1.000 / 1.000 |
| Attacks detected | 3 of 3 |
| Clean logs, alerts raised | 0 |
 
## Known limits
 
- **One user, one big incident.** The test attacks all hit the same user within the same few days, so the detector merges them into a single incident. Spreading attacks across different users would test the incident grouping properly.
- **Fixed baseline.** "Normal" is learned once from the first week. A real system would keep updating it.
- **Simple stage rules.** Stages are assigned from the event type, and the `app` column is not used.
- **Synthetic data.** The logs and attacks are generated for testing. Real logs will be noisier, and the thresholds would need tuning.
## Output format
 
Each incident in the detector's JSON output contains:
 
- `incident_id`, `title`, `users`, `devices`, `ips`
- `start`, `end`, `stages`
- `score` (also saved as `risk_score`)
- `events`: every event with all 8 log fields plus `stage` and `reasons`
- `recommended_actions`: one suggested response per stage
 