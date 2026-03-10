# Threat Intel IOC Checker

A Streamlit web app for checking IPs, domains, and URLs against multiple threat intelligence sources in a single query.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.x-red)

## Features

- **6 threat intel sources** queried in parallel:
  - **WHOIS** — Domain registration data, registrar, age (flags newly registered domains < 30 days)
  - **VirusTotal** — Malicious engine detections, reputation score
  - **AbuseIPDB** — IP abuse confidence score, total reports
  - **URLScan.io** — Live page scan with screenshot, malicious score
  - **Hybrid Analysis** — Sandbox analysis reports, verdict, threat score
  - **ThreatFox** — Malware family mapping, threat types, confidence level

- **Smart IOC parsing:**
  - Accepts raw IPs, domains, or full URLs
  - Auto-extracts domain from URLs (e.g., `https://evil.com/path?q=x` -> `evil.com`)
  - Resolves domains to IPs via DNS for AbuseIPDB lookups
  - Full URL preserved for URLScan.io submissions

- **Dynamic layout** — only enabled services render, no blank columns
- **Toggle services** on/off from the sidebar
- **Rate limit awareness** — displays free tier limits for each API

## Screenshot

```
┌─────────────────────────────────────────────────────┐
│  Threat Intel IOC Checker                           │
│  Enter IOCs (one per line)                          │
│  ┌───────────────────────────────────────────────┐  │
│  │ 8.8.8.8                                       │  │
│  │ suspicious-domain.com                          │  │
│  └───────────────────────────────────────────────┘  │
│  [Scan]                                             │
│                                                     │
│  Results: suspicious-domain.com                     │
│  ┌──────────┬──────────────┬───────────────┐        │
│  │  WHOIS   │  VirusTotal  │   AbuseIPDB   │        │
│  ├──────────┼──────────────┼───────────────┤        │
│  │  Age: 15 │  3/90 mal    │  Confidence:  │        │
│  │  days    │  engines     │  85%          │        │
│  └──────────┴──────────────┴───────────────┘        │
└─────────────────────────────────────────────────────┘
```

## Setup

### 1. Clone and install

```bash
git clone https://github.com/dsnow121/threat-intel-checker.git
cd threat-intel-checker
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure API keys

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

| Service | Free Tier | Get Key |
|---------|-----------|---------|
| VirusTotal | 4 req/min, 500/day | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | 1,000/day | [abuseipdb.com](https://www.abuseipdb.com/register) |
| URLScan.io | 2,000/month | [urlscan.io](https://urlscan.io/user/signup) |
| Hybrid Analysis | 5 req/min, 200/hr | [hybrid-analysis.com](https://www.hybrid-analysis.com/signup) |
| ThreatFox | Free (fair use) | [auth.abuse.ch](https://auth.abuse.ch/) |
| WHOIS | No limit | No key needed |

### 3. Run

```bash
streamlit run app.py
```

Opens at `http://localhost:8501`

**Optional:** Add a shell alias for quick launch:

```bash
echo "alias threatcheck='cd /path/to/threat-intel-checker && source venv/bin/activate && streamlit run app.py'" >> ~/.zshrc
source ~/.zshrc
```

Then just run `threatcheck` from any terminal.

## Usage

1. Enter one or more IOCs in the text area (one per line) — IPs, domains, or full URLs
2. Toggle which services to query in the sidebar
3. Click **Scan**
4. Results display in a dynamic grid grouped by source

### IOC Input Examples

```
8.8.8.8
malware.wicar.org
https://suspicious-site.com/auth/login?redirect=evil
192.168.1.1
example.com
```

## Project Structure

```
threat-intel-checker/
├── app.py              # Main application (all logic + UI)
├── requirements.txt    # Python dependencies
├── .env.example        # API key template
├── .env                # Your API keys (gitignored)
└── .gitignore
```

## License

MIT
