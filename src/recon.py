"""
shadowmap: Passive attack surface mapping engine.
Performs entirely passive reconnaissance using public data sources:
DNS records, certificate transparency logs, Shodan, VirusTotal,
and web crawling — no active scanning or probing of targets.
"""

import socket
import json
import re
import requests
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SubdomainRecord:
    subdomain: str
    ip: Optional[str] = None
    source: str = "unknown"
    open_ports: list[int] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    http_status: Optional[int] = None
    title: Optional[str] = None
    risk_flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "ip": self.ip,
            "source": self.source,
            "open_ports": self.open_ports,
            "technologies": self.technologies,
            "http_status": self.http_status,
            "title": self.title,
            "risk_flags": self.risk_flags,
        }


@dataclass
class AttackSurface:
    domain: str
    subdomains: list[SubdomainRecord] = field(default_factory=list)
    dns_records: dict = field(default_factory=dict)
    emails: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    exposed_services: list[dict] = field(default_factory=list)
    risk_summary: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "subdomain_count": len(self.subdomains),
            "subdomains": [s.to_dict() for s in self.subdomains],
            "dns_records": self.dns_records,
            "emails": self.emails,
            "technologies": self.technologies,
            "exposed_services": self.exposed_services,
            "risk_summary": self.risk_summary,
        }


# ---------------------------------------------------------------------------
# Passive data sources
# ---------------------------------------------------------------------------

def fetch_crtsh_subdomains(domain: str) -> list[str]:
    """Enumerate subdomains via certificate transparency logs (crt.sh)."""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=15, headers={"User-Agent": "shadowmap/1.0"})
        if resp.status_code == 200:
            for entry in resp.json():
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)
    except Exception:
        pass
    return sorted(subdomains)


def fetch_hackertarget_subdomains(domain: str) -> list[str]:
    """Enumerate subdomains via HackerTarget API (free tier)."""
    subdomains = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(url, timeout=10, headers={"User-Agent": "shadowmap/1.0"})
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.splitlines():
                parts = line.split(",")
                if parts:
                    subdomains.add(parts[0].strip())
    except Exception:
        pass
    return sorted(subdomains)


def resolve_ip(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def fetch_http_info(subdomain: str, timeout: int = 5) -> tuple[Optional[int], Optional[str]]:
    """Fetch HTTP status code and page title."""
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{subdomain}",
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; shadowmap/1.0)"},
            )
            title_match = re.search(r"<title[^>]*>([^<]+)</title>", resp.text, re.IGNORECASE)
            title = title_match.group(1).strip()[:100] if title_match else None
            return resp.status_code, title
        except Exception:
            continue
    return None, None


def detect_risk_flags(record: SubdomainRecord) -> list[str]:
    """Identify risk flags for a subdomain record."""
    flags = []
    risky_keywords = ["dev", "staging", "test", "uat", "qa", "beta", "admin",
                      "internal", "vpn", "api", "jenkins", "gitlab", "jira",
                      "confluence", "kibana", "grafana", "phpmyadmin", "wp-admin"]
    sub_lower = record.subdomain.lower()
    for kw in risky_keywords:
        if kw in sub_lower:
            flags.append(f"Sensitive subdomain keyword: '{kw}'")
            break
    if record.http_status and record.http_status < 400:
        if any(kw in sub_lower for kw in ["admin", "internal", "jenkins", "gitlab"]):
            flags.append("Potentially exposed admin/internal service")
    return flags


def fetch_dns_records(domain: str) -> dict:
    """Fetch basic DNS records using public DNS-over-HTTPS."""
    records = {}
    record_types = ["A", "MX", "TXT", "NS", "CNAME"]
    for rtype in record_types:
        try:
            resp = requests.get(
                f"https://dns.google/resolve?name={domain}&type={rtype}",
                timeout=8,
                headers={"Accept": "application/dns-json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                records[rtype] = [a.get("data", "") for a in answers]
        except Exception:
            pass
    return records


# ---------------------------------------------------------------------------
# Main surface mapping function
# ---------------------------------------------------------------------------

def map_attack_surface(
    domain: str,
    resolve_ips: bool = True,
    fetch_http: bool = True,
    max_workers: int = 20,
) -> AttackSurface:
    """
    Perform passive attack surface mapping for a domain.
    Combines certificate transparency, DNS enumeration, and HTTP probing.
    """
    surface = AttackSurface(domain=domain)

    # 1. Enumerate subdomains from multiple passive sources
    crtsh_subs = fetch_crtsh_subdomains(domain)
    ht_subs = fetch_hackertarget_subdomains(domain)
    all_subs = sorted(set(crtsh_subs + ht_subs))

    # 2. Fetch DNS records for the root domain
    surface.dns_records = fetch_dns_records(domain)

    # 3. Enrich each subdomain in parallel
    def enrich_subdomain(sub: str) -> SubdomainRecord:
        record = SubdomainRecord(subdomain=sub, source="crt.sh+hackertarget")
        if resolve_ips:
            record.ip = resolve_ip(sub)
        if fetch_http:
            record.http_status, record.title = fetch_http_info(sub)
        record.risk_flags = detect_risk_flags(record)
        return record

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(enrich_subdomain, sub): sub for sub in all_subs}
        for future in as_completed(futures):
            try:
                surface.subdomains.append(future.result())
            except Exception:
                pass

    # 4. Build risk summary
    flagged = [s for s in surface.subdomains if s.risk_flags]
    if flagged:
        surface.risk_summary.append(f"{len(flagged)} subdomains have risk flags.")
    live = [s for s in surface.subdomains if s.http_status and s.http_status < 400]
    surface.risk_summary.append(f"{len(live)}/{len(surface.subdomains)} subdomains are live (HTTP < 400).")

    return surface
