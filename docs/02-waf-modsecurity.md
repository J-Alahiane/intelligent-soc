# 2. WAF: Nginx and ModSecurity

The WAF VM runs Nginx 1.18.0 as a reverse proxy in front of Juice Shop. ModSecurity v3 (ModSecurity-nginx connector) with OWASP CRS 4.29.0 inspects every request.

## Virtual host

`/etc/nginx/sites-enabled/default`:

```nginx
server {
    listen 80;
    server_name _;
    access_log /var/log/nginx/waf_access.log;
    error_log  /var/log/nginx/waf_error.log;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsecurity/main.conf;
    location / {
        proxy_pass http://192.168.20.51:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

This is the vhost as recorded. Later hardening changed one point: the WAF no longer trusts a client-supplied X-Forwarded-For header.

## Rule load order

`/etc/nginx/modsecurity/main.conf`:

```apache
Include /etc/nginx/modsecurity/modsecurity.conf
Include /etc/nginx/modsecurity/crs/crs-setup.conf
Include /etc/nginx/modsecurity/crs/rules/*.conf
```

## Key ModSecurity settings

| Setting | Value | Why |
|---|---|---|
| `SecRuleEngine` | `DetectionOnly` | Intentional. The WAF records matches without blocking, so the rules can be audited. |
| `SecRequestBodyAccess` | `On` | JSON and XML body processors are enabled. |
| `SecResponseBodyAccess` | `On` | |
| `SecAuditEngine` | `RelevantOnly` | Logs only relevant transactions. |
| `SecAuditLogRelevantStatus` | `"^(?:5\|4(?!04))"` | 5xx and 4xx except 404. |
| `SecAuditLogParts` | `ABFHZ` | |
| Audit log | serial, `/var/log/modsecurity/audit.log` | Shipped to Splunk as `modsecurity:audit`. |
| CRS paranoia level | 1 | Anomaly scoring. The inbound threshold rule is 949110. |

## Logs

| File | Splunk index | Sourcetype |
|---|---|---|
| `/var/log/modsecurity/audit.log` | `waf` | `modsecurity:audit` |
| `/var/log/nginx/waf_access.log` | `waf` | `nginx:waf:access` |
| `/var/log/nginx/waf_error.log` | `waf` | `nginx:waf:error` |

WAF log rotation and disk monitoring are configured. The alert "WAF disk usage" watches the disk (see [Splunk SIEM](04-splunk-siem.md)).
