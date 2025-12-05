"""Heuristic AI insights for Sentinel OneLink packets.
This module scores packets, provides natural-language insights, and suggests actions.
No external services required; everything runs locally for privacy and reliability.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Dict, Tuple

# Known risky ports/services
HIGH_RISK_PORTS = {
    23: "Telnet",
    3389: "Remote Desktop",
    5900: "VNC",
    22: "SSH",
    21: "FTP",
    445: "SMB",
    25: "SMTP",
    1433: "MSSQL",
}

SUSPICIOUS_KEYWORDS = {
    "miner": "Potential crypto-mining activity",
    "torrent": "Peer-to-peer transfer detected",
    "brute": "Possible brute-force utility",
    "meterpreter": "Penetration testing payload detected",
}

COMMON_SERVICES = {
    80: "HTTP",
    8080: "HTTP-Alt",
    443: "HTTPS",
    53: "DNS",
    123: "NTP",
    5000: "UPnP",
    5353: "mDNS",
}

@dataclass
class Insight:
    risk_score: int
    risk_level: str
    summary: str
    recommendation: str


def _extract_ip_port(endpoint: str) -> Tuple[str, int | None]:
    if not endpoint:
        return ("Unknown", None)
    if ":" not in endpoint:
        return (endpoint, None)
    ip_part, port_part = endpoint.rsplit(":", 1)
    try:
        port = int(port_part)
    except ValueError:
        port = None
    return (ip_part, port)


def _score_port(port: int | None) -> Tuple[int, str | None]:
    if port is None:
        return (0, None)
    if port in HIGH_RISK_PORTS:
        return (4, f"Targets {HIGH_RISK_PORTS[port]} (high-value service)")
    if port in COMMON_SERVICES:
        return (1, f"Standard {COMMON_SERVICES[port]} traffic")
    if port > 1024:
        return (1, "High-numbered port (likely ephemeral)")
    return (2, "Unusual low port usage")


def _keyword_hits(summary: str) -> Tuple[int, str | None]:
    lowered = summary.lower()
    for keyword, description in SUSPICIOUS_KEYWORDS.items():
        if keyword in lowered:
            return (3, description)
    return (0, None)


def _score_direction(src_ip: str, dst_ip: str) -> Tuple[int, str | None]:
    try:
        src_private = ipaddress.ip_address(src_ip).is_private
        dst_private = ipaddress.ip_address(dst_ip).is_private
    except ValueError:
        return (0, None)
    if src_private and not dst_private:
        return (1, "Outbound connection to internet")
    if not src_private and src_private != dst_private:
        return (2, "Inbound connection from internet")
    if not src_private and not dst_private:
        return (1, "Traffic between external hosts")
    return (0, "Internal lateral movement")


def analyze_packet(packet: Dict) -> Insight:
    summary = packet.get("summary", "Unknown traffic")
    raw_src = str(packet.get("src", "Unknown"))
    raw_dst = str(packet.get("dst", "Unknown"))
    src_port = packet.get("src_port")
    dst_port = packet.get("dst_port")

    if src_port is None:
        src_ip, inferred = _extract_ip_port(raw_src)
        src_port = inferred
    else:
        src_ip, _ = _extract_ip_port(raw_src)

    if dst_port is None:
        dst_ip, inferred = _extract_ip_port(raw_dst)
        dst_port = inferred
    else:
        dst_ip, _ = _extract_ip_port(raw_dst)

    score = 0
    reasons = []

    port_score, port_reason = _score_port(dst_port)
    score += port_score
    if port_reason:
        reasons.append(port_reason)

    keyword_score, keyword_reason = _keyword_hits(summary)
    score += keyword_score
    if keyword_reason:
        reasons.append(keyword_reason)

    direction_score, direction_reason = _score_direction(src_ip, dst_ip)
    score += direction_score
    if direction_reason:
        reasons.append(direction_reason)

    if packet.get("source") == "system" and "Unknown" in summary:
        score += 2
        reasons.append("System-level monitor detected unknown process")

    proto = str(packet.get("proto", "?")).upper()
    if proto in {"UDP"} and dst_port in HIGH_RISK_PORTS:
        score += 1
        reasons.append("Uncommon protocol for sensitive port")

    if score <= 2:
        level = "Low"
        recommendation = "Monitor normally; no action needed."
    elif score <= 5:
        level = "Medium"
        recommendation = "Verify the device or application initiating this traffic."
    elif score <= 8:
        level = "High"
        recommendation = "Investigate immediately; consider blocking or isolating the device."
    else:
        level = "Critical"
        recommendation = "Likely malicious. Disconnect the device and run a full scan."

    if not reasons:
        reasons.append("Routine traffic pattern detected")

    insight_summary = f"AI insight for {proto} traffic: {', '.join(reasons)}."

    return Insight(
        risk_score=min(score, 10),
        risk_level=level,
        summary=insight_summary,
        recommendation=recommendation,
    )
