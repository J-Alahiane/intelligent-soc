# Intelligent SOC: WAF, SIEM and AI-Assisted Automation

A three-network SOC lab built around OWASP Juice Shop, a deliberately vulnerable web application. A dual-homed WAF VM runs Nginx with ModSecurity v3 and the OWASP Core Rule Set (CRS) 4.29.0, and Suricata 8.0.8 inspects the same traffic on the same VM. A Splunk Universal Forwarder ships all logs to Splunk Enterprise, which correlates WAF and IDS events into one incident alert, maps detections to MITRE ATT&CK (v20) and shows everything on a Dashboard Studio dashboard. n8n adds two automations, both with a human in control: AI triage of each correlated alert with Google Gemini, and AI-proposed ATT&CK mappings that a human approves before they are applied.

## Architecture

```mermaid
flowchart LR
  subgraph NET2["NET 2 · 192.168.40.0/24"]
    K["Kali Linux<br/>192.168.40.50"]
  end
  subgraph WAFVM["WAF VM · 192.168.40.51 / 192.168.20.54"]
    W["Nginx + ModSecurity v3<br/>OWASP CRS 4.29.0 (DetectionOnly)"]
    S["Suricata 8.0.8<br/>ens33 + ens37"]
    U["Splunk Universal Forwarder"]
  end
  subgraph NET1["NET 1 · 192.168.20.0/24"]
    J["OWASP Juice Shop<br/>192.168.20.51:8080"]
  end
  P["pfSense 2.7.2"]
  subgraph NET3["NET 3 · 192.168.30.0/24"]
    SP["Splunk Enterprise 10.4.1<br/>192.168.30.51"]
    N["n8n 2.47.7<br/>127.0.0.1:5678"]
  end
  G["Google Gemini API<br/>gemini-3.5-flash-lite"]
  A["SOC analyst"]
  NAV["ATT&CK Navigator layer"]
  K -- "HTTP attacks" --> W
  W -- "proxied requests" --> J
  W -. logs .-> U
  S -. eve.json .-> U
  U -. "TCP 9997" .-> P -.-> SP
  SP -- "alert webhook" --> N
  N -- "prompt" --> G
  G -- "JSON answer" --> N
  N -- "HEC → index soc_ai" --> SP
  SP -- "dashboard" --> A
  A -- "approval form" --> N
  N -- "layer JSON" --> NAV
```

## Key capabilities

- Two detection layers on one gateway: ModSecurity + CRS (application) and Suricata with ET Open rules (network).
- pfSense segmentation: the attacker can reach the application only through the WAF.
- Splunk correlation of WAF and IDS events on client IP and URL within 5 seconds, with HIGH / MEDIUM / LOW confidence.
- Detection and health alerts, tagged with ATT&CK technique IDs.
- MITRE ATT&CK v20 mapping in the `attack_mapping` lookup and a generated ATT&CK Navigator layer.
- AI triage: each correlated alert goes to Gemini; the validated, advisory-only answer is written back to Splunk.
- Human-approved ATT&CK mapping: AI proposals, an approval form, backup, verified write, decision log and rollback.
- Dashboard Studio dashboard covering health, detections, correlation, ATT&CK, AI triage and mapping review.

## Technology

| Component | Version |
|---|---|
| Nginx | 1.18.0 (Ubuntu) |
| ModSecurity | v3 with the ModSecurity-nginx connector |
| OWASP CRS | 4.29.0 |
| Suricata | 8.0.8, ET Open rules |
| Splunk Enterprise | 10.4.1 |
| pfSense | 2.7.2 |
| n8n | 2.47.7 (npm, Node.js 24.22.3) |
| AI model | Google Gemini API, free tier, `gemini-3.5-flash-lite` |
| MITRE ATT&CK | Enterprise v20 (collection 20.1) |

## Network

| Network | Subnet | Host | Address | Role |
|---|---|---|---|---|
| NET 2 | 192.168.40.0/24 | Kali Linux | 192.168.40.50 | Attacker (controlled tests) |
| NET 2 / NET 1 | — | WAF VM (Ubuntu 22.04, host `waf-vm`) | ens33 192.168.40.51, ens37 192.168.20.54 | Nginx + ModSecurity v3 + CRS 4.29.0, Suricata 8.0.8, Universal Forwarder |
| NET 1 | 192.168.20.0/24 | OWASP Juice Shop | 192.168.20.51:8080 | Target web application |
| NET 3 | 192.168.30.0/24 | Splunk Enterprise 10.4.1 (Windows 10 VM) | 192.168.30.51 (receiving port 9997) | SIEM, dashboard, lookups; n8n runs on the same VM |
| — | — | pfSense 2.7.2 | gateway of each subnet | Segmentation, routing, NTP source |

## Documentation

1. [Architecture](docs/01-architecture.md)
2. [WAF: Nginx and ModSecurity](docs/02-waf-modsecurity.md)
3. [Suricata IDS](docs/03-suricata-ids.md)
4. [Splunk SIEM](docs/04-splunk-siem.md): forwarding, indexes, macros, correlation, alerts, dashboard
5. [MITRE ATT&CK mapping](docs/05-mitre-attack.md)
6. [n8n AI triage](docs/06-n8n-ai-triage.md)
7. [n8n ATT&CK mapping](docs/07-n8n-attack-mapping.md): proposals, approval, layer
8. [Tests and results](docs/08-tests-and-results.md)
9. [Troubleshooting](docs/09-troubleshooting.md)
10. [Security considerations](docs/10-security-considerations.md)
11. [Demo runbook](docs/11-demo-runbook.md)

Other folders: [`scripts/`](scripts/) (ATT&CK lookup and layer generators), [`splunk/`](splunk/) (dashboard JSON and `attack_mapping.csv`), [`presentation/`](presentation/) (project slides).

## Screenshots

![Splunk Dashboard Studio overview](docs/images/01-dashboard-overview.png)
*SOC Lab - WAF + IDS Overview: health KPIs, WAF/IDS KPIs and timelines.*

![Dashboard AI triage section](docs/images/16-dashboard-ai-triage.png)
*AI triage suggestions (advisory only) with a real result for a correlated incident.*

![n8n ATT&CK mapping approval workflow](docs/images/25-n8n-approval-workflow-final.png)
*Approval workflow: checks, backup, write, verification and decision logging.*

![ATT&CK Navigator layer](docs/images/08-attack-navigator-layer.png)
*Navigator layer generated from the `attack_mapping` lookup.*

## Author

Jihad Mohamed Alahiane, cybersecurity engineering student, ENSA Kénitra.

Built for education in an isolated lab. Attack traffic was generated only against lab systems.
