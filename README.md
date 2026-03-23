# shadowmap 🌐

> **Passive attack surface mapper** using certificate transparency logs, DNS enumeration, and AI-powered risk analysis. Zero active scanning — completely safe to run against any target.

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://github.com/rawqubit/shadowmap/actions/workflows/ci.yml/badge.svg)](https://github.com/rawqubit/shadowmap/actions/workflows/ci.yml)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4.1-412991?style=flat-square&logo=openai&logoColor=white)](https://openai.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Security](https://img.shields.io/badge/Category-Reconnaissance-red?style=flat-square)]()

---

## Overview

Before attacking or defending a system, you need to understand its **attack surface** — the sum of all externally accessible entry points. `shadowmap` automates this discovery using **entirely passive techniques**, meaning it never sends a single packet directly to the target infrastructure.

### Data Sources

| Source | What it provides |
|--------|-----------------|
| **crt.sh** (Certificate Transparency) | Subdomains from TLS certificate issuance history |
| **HackerTarget API** | Additional subdomain enumeration |
| **Google DNS-over-HTTPS** | A, MX, TXT, NS, CNAME records |
| **HTTP probing** | Live status codes, page titles, technology hints |
| **AI analysis** | Risk classification, attack path recommendations |

---

## Features

- **Zero active scanning** — all data comes from public sources and passive HTTP probing
- **Certificate transparency enumeration** — discovers subdomains that DNS brute-forcing would miss
- **Parallel enrichment** — resolves IPs and probes HTTP for all subdomains concurrently
- **Risk flagging** — automatically highlights dev, staging, admin, and internal subdomains
- **AI attack surface analysis** — GPT-4.1 identifies high-risk assets and recommends investigation paths
- **Multiple output formats** — rich terminal tables, JSON (for pipeline integration), Markdown reports
- **Configurable concurrency** — tune worker count for speed vs. stealth

---

## Installation

```bash
git clone https://github.com/rawqubit/shadowmap.git
cd shadowmap
pip install -r requirements.txt
export OPENAI_API_KEY="sk-..."  # Required only for --ai-analysis
```

---

## Usage

```bash
# Basic passive recon
python main.py map example.com

# With AI risk analysis and report
python main.py map example.com --ai-analysis --report surface_report.md

# JSON output for pipeline integration
python main.py map example.com --output json | jq '.subdomains[] | select(.risk_flags | length > 0)'

# Faster scan without HTTP probing
python main.py map example.com --no-http --workers 50

# Filter high-risk subdomains
python main.py map example.com --output json | jq '.subdomains[] | select(.risk_flags | length > 0) | .subdomain'
```

---

## Architecture

```
shadowmap/
├── main.py          # CLI entrypoint + AI analysis
├── src/
│   └── recon.py     # Passive recon engine
└── requirements.txt
```

### Recon Pipeline

```
Domain Input
    │
    ├──▶ crt.sh (Certificate Transparency)
    ├──▶ HackerTarget API
    │         │
    │         ▼
    │    Subdomain List (deduplicated)
    │         │
    │    ┌────┴────────────────────────────┐
    │    │  Parallel Enrichment (N workers) │
    │    │  ┌─────────────┐ ┌────────────┐ │
    │    │  │ DNS Resolve │ │ HTTP Probe │ │
    │    │  └─────────────┘ └────────────┘ │
    │    └────────────────────────────────┘
    │         │
    ├──▶ DNS Records (Google DoH)
    │         │
    ▼         ▼
    AttackSurface Object
         │
         ▼ (--ai-analysis)
    GPT-4.1 Risk Analysis
         │
         ▼
    Report / JSON / Table
```

---

## Example Output

```
┌─────────────────────────────────────────────────────────────────┐
│ shadowmap — passive recon for example.com                       │
│ HTTP probing: enabled | Workers: 20                             │
└─────────────────────────────────────────────────────────────────┘

DNS Records
┌──────┬──────────────────────────────────────────────────┐
│ Type │ Records                                          │
├──────┼──────────────────────────────────────────────────┤
│ A    │ 93.184.216.34                                    │
│ MX   │ 0 .                                              │
│ NS   │ a.iana-servers.net. b.iana-servers.net.          │
└──────┴──────────────────────────────────────────────────┘

Subdomains (47 found)
┌──────────────────────────┬───────────────┬──────┬──────────────────────┬──────────────────────────────────┐
│ Subdomain                │ IP            │ HTTP │ Title                │ Risk Flags                       │
├──────────────────────────┼───────────────┼──────┼──────────────────────┼──────────────────────────────────┤
│ admin.example.com        │ 93.184.216.35 │ 200  │ Admin Dashboard      │ Sensitive keyword: 'admin'       │
│ staging.example.com      │ 93.184.216.36 │ 200  │ Staging Environment  │ Sensitive keyword: 'staging'     │
│ jenkins.example.com      │ 93.184.216.37 │ 200  │ Jenkins CI           │ Sensitive keyword: 'jenkins'     │
└──────────────────────────┴───────────────┴──────┴──────────────────────┴──────────────────────────────────┘
```

---

## Ethical Use

`shadowmap` is designed for:
- Security teams assessing their own organization's attack surface
- Penetration testers with written authorization
- Bug bounty hunters operating within program scope
- Security researchers studying internet-wide exposure

**Do not use this tool against targets you do not have permission to assess.**

---


## Demo

```
$ shadowmap --target example.com --output report.md

 shadowmap v1.0.0  Passive Attack Surface Mapper
 Target: example.com
 Mode: Passive only (zero packets sent to target)

 Phase 1: Certificate Transparency Logs
  Querying crt.sh... 23 certificates found
  Querying Censys...  17 additional SANs discovered

 Phase 2: DNS Enumeration
  A records:      4 IP addresses
  MX records:     2 mail servers
  NS records:     4 nameservers (2 external DNS providers)
  TXT records:    SPF, DMARC, Google verification, 3 others
  CNAMEs:         8 (CDN, SaaS, internal services)

 Phase 3: AI Risk Analysis
  Discovered 31 unique subdomains

 High Priority Assets
  api.example.com        -> 203.0.113.42   [API endpoint, no WAF detected]
  admin.example.com      -> 203.0.113.51   [Admin panel, publicly accessible]
  staging.example.com    -> 203.0.113.19   [Staging env, may have weaker controls]

 Report saved to report.md
 Total assets mapped: 31 subdomains, 4 IPs, 2 mail servers
```

## Contributing

Contributions welcome. Priority areas:
- Additional passive data sources (Shodan free tier, SecurityTrails, etc.)
- Technology fingerprinting from HTTP headers
- Historical data comparison to detect new exposures

---

## License

MIT License — see [LICENSE](LICENSE) for details.
