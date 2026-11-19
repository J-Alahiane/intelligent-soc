#!/usr/bin/env python3
"""Build an ATT&CK Navigator layer from attack_mapping.csv.
Usage: python3 build_layer.py attack_mapping.csv soc_lab_attack_layer.json"""
import csv, json, sys, collections
src, dst = sys.argv[1], sys.argv[2]
rows = list(csv.DictReader(open(src, newline="")))
SHORT = {"TA0043":"reconnaissance","TA0042":"resource-development","TA0001":"initial-access","TA0002":"execution",
         "TA0003":"persistence","TA0004":"privilege-escalation","TA0005":"defense-evasion","TA0006":"credential-access",
         "TA0007":"discovery","TA0008":"lateral-movement","TA0009":"collection","TA0011":"command-and-control",
         "TA0010":"exfiltration","TA0040":"impact"}
COL = {"tested":"#53a051","partial":"#b5d55a","untested":"#f8be34","gap (planned)":"#dc4e41"}
tech = collections.OrderedDict()
for r in rows:
    if r["technique_id"] == "N/A": continue
    t = tech.setdefault(r["technique_id"], {"name":r["technique"],"tactic":SHORT[r["tactic_id"]],"tested":[],"untested":[],"planned":[]})
    t[r["coverage_status"]].append(r["detection_key"])
techs = []
for tid, t in tech.items():
    if t["planned"] and not t["tested"] and not t["untested"]: st = "gap (planned)"
    elif not t["untested"] and not t["planned"]: st = "tested"
    elif t["tested"]: st = "partial"
    else: st = "untested"
    cm = f'{t["name"]}: {st}. Tested detections: {len(t["tested"])}, untested: {len(t["untested"])}, planned: {len(t["planned"])}.'
    if t["untested"]: cm += " Not yet tested: " + ", ".join(t["untested"]) + "."
    if t["planned"]: cm += " Planned: " + ", ".join(t["planned"]) + "."
    techs.append({"techniqueID":tid,"tactic":t["tactic"],"color":COL[st],"comment":cm,"enabled":True,
        "metadata":[{"name":"status","value":st},{"name":"tested detections","value":", ".join(t["tested"]) or "-"},
                    {"name":"not yet tested","value":", ".join(t["untested"]+t["planned"]) or "-"}],
        "links":[],"showSubtechniques":"." not in tid and any(x.startswith(tid+".") for x in tech)})
layer = {"name":"SOC Lab - detection coverage (WAF + IDS)",
 "versions":{"attack":"20","navigator":"5.2.0","layer":"4.5"},"domain":"enterprise-attack",
 "description":"Green = all mapped detections tested. Light green = partly tested. Amber = detection exists, not yet tested. Red = planned, not built. Source: Splunk lookup attack_mapping.",
 "filters":{"platforms":["Linux","Windows","macOS","Network","PRE","Containers","IaaS","SaaS","Office Suite","Identity Provider"]},
 "sorting":0,"layout":{"layout":"side","aggregateFunction":"average","showID":True,"showName":True,"showAggregateScores":False,"countUnscored":False,"expandedSubtechniques":"annotated"},
 "hideDisabled":False,"techniques":techs,
 "gradient":{"colors":["#ff6666ff","#ffe766ff","#8ec843ff"],"minValue":0,"maxValue":100},
 "legendItems":[{"label":"Tested","color":COL["tested"]},{"label":"Partly tested","color":COL["partial"]},
                {"label":"Detection exists, untested","color":COL["untested"]},{"label":"Gap (planned)","color":COL["gap (planned)"]}],
 "metadata":[],"links":[],"showTacticRowBackground":False,"tacticRowBackground":"#dddddd",
 "selectTechniquesAcrossTactics":True,"selectSubtechniquesWithParent":False,"selectVisibleTechniques":False}
json.dump(layer, open(dst, "w"), indent=2)
for t in techs: print(f'{t["techniqueID"]:10} {t["metadata"][0]["value"]:14} {t["comment"][:100]}')
