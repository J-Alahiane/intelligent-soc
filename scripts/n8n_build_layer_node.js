const fin = [], pre = [];
for (const line of String($input.first().json.data ?? "").split("\n")) {
  if (!line.trim()) continue;
  let o; try { o = JSON.parse(line); } catch (e) { continue; }
  if (o.result && o.result.detection_key) (o.preview === false ? fin : pre).push(o.result);
}
const data = fin.length ? fin : pre;
if (data.length < 30) throw new Error("Mapping looks too small: " + data.length);

const SHORT = { TA0043: "reconnaissance", TA0042: "resource-development", TA0001: "initial-access", TA0002: "execution",
  TA0003: "persistence", TA0004: "privilege-escalation", TA0005: "defense-evasion", TA0006: "credential-access",
  TA0007: "discovery", TA0008: "lateral-movement", TA0009: "collection", TA0011: "command-and-control",
  TA0010: "exfiltration", TA0040: "impact" };
const COL = { tested: "#53a051", partial: "#b5d55a", untested: "#f8be34", "gap (planned)": "#dc4e41" };

const tech = new Map();
for (const r of data) {
  if (r.technique_id === "N/A") continue;
  if (!/^T\d{4}(\.\d{3})?$/.test(r.technique_id) || !SHORT[r.tactic_id]) continue;
  if (!tech.has(r.technique_id)) tech.set(r.technique_id, { name: r.technique, tactic: SHORT[r.tactic_id], tested: [], untested: [], planned: [] });
  const st = ["tested", "untested", "planned"].includes(r.coverage_status) ? r.coverage_status : "untested";
  tech.get(r.technique_id)[st].push(r.detection_key);
}

const techs = [];
for (const [tid, t] of tech) {
  let st;
  if (t.planned.length && !t.tested.length && !t.untested.length) st = "gap (planned)";
  else if (!t.untested.length && !t.planned.length) st = "tested";
  else if (t.tested.length) st = "partial";
  else st = "untested";
  let cm = `${t.name}: ${st}. Tested detections: ${t.tested.length}, untested: ${t.untested.length}, planned: ${t.planned.length}.`;
  if (t.untested.length) cm += " Not yet tested: " + t.untested.join(", ") + ".";
  if (t.planned.length) cm += " Planned: " + t.planned.join(", ") + ".";
  techs.push({ techniqueID: tid, tactic: t.tactic, color: COL[st], comment: cm, enabled: true,
    metadata: [{ name: "status", value: st },
      { name: "tested detections", value: t.tested.join(", ") || "-" },
      { name: "not yet tested", value: t.untested.concat(t.planned).join(", ") || "-" }],
    links: [],
    showSubtechniques: !tid.includes(".") && [...tech.keys()].some(x => x.startsWith(tid + ".")) });
}

const layer = { name: "SOC Lab - detection coverage (WAF + IDS)",
  versions: { attack: "20", navigator: "5.2.0", layer: "4.5" }, domain: "enterprise-attack",
  description: "Green = all mapped detections tested. Light green = partly tested. Amber = detection exists, not yet tested. Red = planned, not built. Source: Splunk lookup attack_mapping.",
  filters: { platforms: ["Linux", "Windows", "macOS", "Network", "PRE", "Containers", "IaaS", "SaaS", "Office Suite", "Identity Provider"] },
  sorting: 0, layout: { layout: "side", aggregateFunction: "average", showID: true, showName: true, showAggregateScores: false, countUnscored: false, expandedSubtechniques: "annotated" },
  hideDisabled: false, techniques: techs,
  gradient: { colors: ["#ff6666ff", "#ffe766ff", "#8ec843ff"], minValue: 0, maxValue: 100 },
  legendItems: [{ label: "Tested", color: COL.tested }, { label: "Partly tested", color: COL.partial },
    { label: "Detection exists, untested", color: COL.untested }, { label: "Gap (planned)", color: COL["gap (planned)"] }],
  metadata: [], links: [], showTacticRowBackground: false, tacticRowBackground: "#dddddd",
  selectTechniquesAcrossTactics: true, selectSubtechniquesWithParent: false, selectVisibleTechniques: false };

return [{ json: { layer } }];
