#!/usr/bin/env python3
"""Build attack_techniques.csv (official ATT&CK Enterprise technique allowlist) from MITRE's STIX bundle.

Usage:
  python build_techniques.py                      # download the latest bundle from GitHub
  python build_techniques.py <file.json|URL> <out.csv>

Output columns: technique_id, name, tactic_ids, tactic_names, is_subtechnique
Revoked and deprecated techniques are skipped. Used by n8n to validate AI proposals:
the AI may only choose an ID that exists here; names and tactics are copied from this file."""
import csv, json, sys, urllib.request

DEFAULT_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
out = sys.argv[2] if len(sys.argv) > 2 else "attack_techniques.csv"

if src.startswith("https://"):
    with urllib.request.urlopen(src, timeout=120) as r:
        bundle = json.load(r)
else:
    with open(src, encoding="utf-8") as f:
        bundle = json.load(f)

objs = bundle["objects"]
version = next((o.get("x_mitre_version") for o in objs if o.get("type") == "x-mitre-collection"), "unknown")

# tactic shortname -> (TA id, display name)
tactics = {}
for o in objs:
    if o.get("type") == "x-mitre-tactic" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
        ta = next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if ta:
            tactics[o["x_mitre_shortname"]] = (ta, o["name"])

rows = []
for o in objs:
    if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
        continue
    tid = next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
    if not tid:
        continue
    phases = [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
    ta_ids = [tactics[p][0] for p in phases if p in tactics]
    ta_names = [tactics[p][1] for p in phases if p in tactics]
    rows.append([tid, o["name"], ";".join(ta_ids), ";".join(ta_names), "yes" if "." in tid else "no"])

rows.sort(key=lambda r: r[0])
with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["technique_id", "name", "tactic_ids", "tactic_names", "is_subtechnique"])
    w.writerows(rows)

print(f"ATT&CK collection version: {version}")
print(f"techniques written: {len(rows)} ({sum(1 for r in rows if r[4]=='no')} techniques, {sum(1 for r in rows if r[4]=='yes')} sub-techniques) -> {out}")
for want in ("T1190", "T1595.003", "T1059", "T1110"):
    hit = [r for r in rows if r[0] == want]
    print(want, "->", hit[0][1:4] if hit else "MISSING")
