import re
import json
from typing import List
from app.models.event import LogEvent


def parse_logs(raw_text: str) -> List[LogEvent]:
    events = []
    lines = raw_text.splitlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # ---------- JSON LOGS ----------
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                events.append(LogEvent(
                    timestamp=data.get("timestamp", "unknown"),
                    source="application",
                    event_type=data.get("level", "info"),
                    severity=data.get("level", "INFO"),
                    user=data.get("user"),
                    ip=data.get("ip"),
                    action=data.get("message"),
                    raw=line
                ))
                continue
            except:
                pass

        # ---------- APACHE LOGS ----------
        apache_match = re.match(r'(\S+) - - \[(.*?)\] "(.*?)" (\d{3})', line)
        if apache_match:
            ip, timestamp, request, status = apache_match.groups()
            severity = "HIGH" if status.startswith("4") or status.startswith("5") else "LOW"
            events.append(LogEvent(
                timestamp=timestamp,
                source="apache",
                event_type="http_request",
                severity=severity,
                ip=ip,
                action=request,
                raw=line
            ))
            continue

        # ---------- SSH LOGS ----------
        ssh_match = re.search(r"sshd.*(Accepted|Failed).*for (\w+) from (\S+)", line)
        if ssh_match:
            status, user, ip = ssh_match.groups()
            severity = "HIGH" if status == "Failed" else "LOW"
            events.append(LogEvent(
                timestamp="unknown",
                source="ssh",
                event_type="authentication",
                severity=severity,
                user=user,
                ip=ip,
                action=status,
                raw=line
            ))
            continue

        # ---------- FIREWALL LOGS ----------
        fw_match = re.match(r"(\S+) (ALLOW|BLOCK) (\S+) (\S+) -> (\S+)", line)
        if fw_match:
            timestamp, action, proto, src, dst = fw_match.groups()
            ip = src.split(":")[0]
            severity = "HIGH" if action == "BLOCK" else "LOW"
            events.append(LogEvent(
                timestamp=timestamp,
                source="firewall",
                event_type="network",
                severity=severity,
                ip=ip,
                action=action,
                resource=dst,
                raw=line
            ))
            continue

        # ---------- FALLBACK ----------
        events.append(LogEvent(
            timestamp="unknown",
            source="unknown",
            event_type="unknown",
            severity="LOW",
            raw=line
        ))

    return events
    