# Intelligent SOC: WAF, SIEM & Threat Intelligence

> Documentation repository for my engineering academic project (PFA, SOC & Threat Hunting): a small, fully virtualized Security Operations Center that correlates web-application-firewall events with network intrusion detection in Splunk, to cut false-positive alerts.

This repository contains documentation only (architecture, design decisions, detection logic). It holds no credentials, real logs or exploit code.

## Objectives

- Build a realistic SOC lab: protected web app, attacker machine, SIEM.
- Detect web attacks at two layers (WAF at the application layer, Suricata IDS at the network layer).
- **Correlate both sources in Splunk** so an alert fires with higher confidence and fewer false positives.
- Maintain health monitoring so the pipeline can't silently fail.

## Architecture

| Network | Role |
|---|---|
| NET1 (192.168.20.0/24) | Vulnerable web application behind the WAF |
| NET2 (192.168.40.0/24) | Attacker machine (Kali Linux) |
| NET3 (192.168.30.0/24) | Splunk Enterprise (Windows 10 host) |

<!-- TODO: add architecture diagram (docs/architecture.png) -->

## Stack

- **WAF:** Nginx + ModSecurity v3 with OWASP Core Rule Set
- **IDS:** Suricata 8.0.8 (ET Open rule set), capturing on the WAF VM
- **SIEM:** Splunk Enterprise + Universal Forwarders
- **Threat intelligence & framework:** MISP, MITRE ATT&CK mapping
- **Network analysis:** Zeek
- **Automation:** n8n

## Project phases

1. **Suricata deployment.** Suricata installed on the same VM as the WAF, capturing on both interfaces. `eve.json` is shipped to Splunk (index `security`, sourcetype `suricata:eve`, host `waf-vm`).
2. **Correlation and rule optimization.** WAF logs and Suricata alerts are joined in Splunk (macro `corr_incidents`; alert *SOC - Correlated incident (WAF/IDS)*). Redundant report-style alerts were retired, and remaining alerts received explicit trigger conditions and throttling.
3. **Dashboard.** Visualization of correlated incidents and pipeline health.

## Detections

- Correlated incident (WAF + IDS)
- Port scan (Suricata)
- WAF bypass attempts
- Low-and-slow scanning (100+ distinct paths in 60 minutes, peaking under 30 per minute)
- Backend availability (HTTP 502/503/504)

## Reliability

- Alerts for Suricata capture/ingest health, packet drops and heartbeat.
- A systemd watchdog timer on the WAF VM restarts Suricata if capture stalls (a known issue when the VM resumes from suspend).

## Methodology

Each phase was validated before moving to the next. A baseline of normal browsing was recorded from the attacker machine before testing attacks, to measure false positives.

## Status

Sections 1 and 2 complete; dashboard in progress.

## Repository layout (planned)

```
docs/            architecture, design decisions
detections/      detection logic descriptions
screenshots/     dashboards and results
```

## Disclaimer

Built for education in an isolated lab. Attack traffic was generated only against systems I own.
