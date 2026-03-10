"""
Threat Intel IOC Checker — Streamlit Web UI
Checks IPs, domains, and URLs against multiple threat intel sources
"""

import re
import os
import time
import socket
import requests
import whois
import streamlit as st
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()


# ─── IOC Parsing ─────────────────────────────────────────────────────────────

def parse_ioc(raw: str) -> dict:
    """
    Parse raw input into structured IOC info.
    Returns dict with 'domain', 'ip', 'full_url', and 'type'.
    - Full URLs get domain extracted for VT/AbuseIPDB, full URL kept for URLScan
    - Plain domains/IPs pass through as-is
    """
    raw = raw.strip()
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", raw))

    if is_ip:
        return {"raw": raw, "lookup": raw, "full_url": raw, "type": "ip", "resolved_ip": raw}

    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        domain = parsed.hostname or raw
        resolved_ip = _resolve_domain(domain)
        return {"raw": raw, "lookup": domain, "full_url": raw, "type": "url", "resolved_ip": resolved_ip}

    # Plain domain
    resolved_ip = _resolve_domain(raw)
    return {"raw": raw, "lookup": raw, "full_url": raw, "type": "domain", "resolved_ip": resolved_ip}


def _resolve_domain(domain: str) -> str | None:
    """Resolve domain to IP via DNS. Returns None on failure."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


# ─── API Functions ───────────────────────────────────────────────────────────

def check_virustotal(ioc: str) -> dict:
    key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not key:
        return {"error": "VIRUSTOTAL_API_KEY not set"}

    headers = {"x-apikey": key}
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc))

    if is_ip:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

    data = resp.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})

    result = {
        "source": "VirusTotal",
        "ioc": ioc,
        "type": "IP" if is_ip else "Domain",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": sum(stats.values()) if stats else 0,
        "reputation": data.get("reputation", 0),
    }

    if is_ip:
        result["country"] = data.get("country", "unknown")
        result["as_owner"] = data.get("as_owner", "unknown")
    else:
        result["registrar"] = data.get("registrar", "unknown")

    return result


def check_abuseipdb(ip_address: str) -> dict:
    key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not key:
        return {"error": "ABUSEIPDB_API_KEY not set"}

    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
        return {"skipped": True, "reason": "AbuseIPDB only supports IP addresses"}

    headers = {"Key": key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers, params=params, timeout=30,
        )
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

    data = resp.json().get("data", {})
    return {
        "source": "AbuseIPDB",
        "ioc": ip_address,
        "type": "IP",
        "abuse_confidence": data.get("abuseConfidenceScore", 0),
        "country": data.get("countryCode", "unknown"),
        "isp": data.get("isp", "unknown"),
        "domain": data.get("domain", "unknown"),
        "total_reports": data.get("totalReports", 0),
        "is_whitelisted": data.get("isWhitelisted", False),
        "last_reported": data.get("lastReportedAt"),
    }


def check_urlscan(ioc: str) -> dict:
    key = os.environ.get("URLSCAN_API_KEY", "")
    if not key:
        return {"error": "URLSCAN_API_KEY not set"}

    # URLScan needs a URL — if given IP/domain, wrap it
    if not ioc.startswith(("http://", "https://")):
        scan_target = f"http://{ioc}"
    else:
        scan_target = ioc

    headers = {"API-Key": key, "Content-Type": "application/json"}

    try:
        resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": scan_target, "visibility": "public"},
            timeout=30,
        )
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

    uuid = resp.json().get("uuid")
    if not uuid:
        return {"error": "No UUID returned from URLScan"}

    # Poll for results
    time.sleep(15)
    for attempt in range(6):
        try:
            result_resp = requests.get(
                f"https://urlscan.io/api/v1/result/{uuid}/", timeout=30
            )
            if result_resp.status_code == 200:
                data = result_resp.json()
                page = data.get("page", {})
                verdicts = data.get("verdicts", {}).get("overall", {})
                return {
                    "source": "URLScan",
                    "ioc": ioc,
                    "type": "URL",
                    "url_scanned": page.get("url", ""),
                    "domain": page.get("domain", ""),
                    "ip": page.get("ip", ""),
                    "country": page.get("country", ""),
                    "server": page.get("server", ""),
                    "malicious": verdicts.get("malicious", False),
                    "score": verdicts.get("score", 0),
                    "categories": verdicts.get("categories", []),
                    "screenshot": data.get("task", {}).get("screenshotURL", ""),
                    "result_url": f"https://urlscan.io/result/{uuid}/",
                }
            elif result_resp.status_code == 404:
                time.sleep(10)
            else:
                return {"error": f"HTTP {result_resp.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    return {"error": "Timed out waiting for URLScan results"}


def check_hybrid_analysis(ioc: str, ioc_type: str) -> dict:
    key = os.environ.get("HYBRID_ANALYSIS_API_KEY", "")
    if not key:
        return {"error": "HYBRID_ANALYSIS_API_KEY not set"}

    headers = {
        "api-key": key,
        "User-Agent": "Falcon Sandbox",
        "Accept": "application/json",
    }

    # Use search/terms to find sandbox reports matching this IOC
    # For URLs, search by domain since HA indexes by domain not full URL
    if ioc_type == "ip":
        payload = {"host": ioc}
    else:
        payload = {"domain": ioc}

    try:
        resp = requests.post(
            "https://hybrid-analysis.com/api/v2/search/terms",
            headers=headers,
            data=payload,
            timeout=30,
        )
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

    data = resp.json()
    results = data.get("result", [])

    if not results:
        return {
            "source": "Hybrid Analysis",
            "ioc": ioc,
            "total_reports": 0,
            "verdict": "No sandbox reports found",
        }

    # Summarize the most recent/relevant reports
    verdicts = []
    threat_names = set()
    for r in results[:10]:
        v = r.get("verdict")
        if v:
            verdicts.append(v)
        name = r.get("vx_family")
        if name:
            threat_names.add(name)

    malicious_count = verdicts.count("malicious")
    suspicious_count = verdicts.count("suspicious")

    top = results[0]
    return {
        "source": "Hybrid Analysis",
        "ioc": ioc,
        "total_reports": len(results),
        "malicious_reports": malicious_count,
        "suspicious_reports": suspicious_count,
        "threat_names": list(threat_names) if threat_names else [],
        "top_verdict": top.get("verdict", "unknown"),
        "top_threat_score": top.get("threat_score"),
        "top_env": top.get("environment_description", ""),
        "top_submit_name": top.get("submit_name", ""),
        "top_analysis_date": top.get("analysis_start_time", ""),
    }


def check_threatfox(ioc: str) -> dict:
    key = os.environ.get("THREATFOX_API_KEY", "")
    if not key:
        return {"error": "THREATFOX_API_KEY not set"}

    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": key},
            json={"query": "search_ioc", "search_term": ioc},
            timeout=30,
        )
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

    data = resp.json()
    if data.get("query_status") == "no_result":
        return {"source": "ThreatFox", "ioc": ioc, "status": "not_found"}

    results = data.get("data", [])
    if not results:
        return {"source": "ThreatFox", "ioc": ioc, "status": "not_found"}

    malware_families = set()
    threat_types = set()
    tags_all = set()
    for r in results[:10]:
        if r.get("malware"):
            malware_families.add(r["malware"])
        if r.get("threat_type"):
            threat_types.add(r["threat_type"])
        for tag in r.get("tags", []) or []:
            tags_all.add(tag)

    top = results[0]
    return {
        "source": "ThreatFox",
        "ioc": ioc,
        "status": "found",
        "total_matches": len(results),
        "malware_families": list(malware_families),
        "threat_types": list(threat_types),
        "tags": list(tags_all),
        "top_malware": top.get("malware", "unknown"),
        "top_threat_type": top.get("threat_type", "unknown"),
        "top_confidence": top.get("confidence_level", 0),
        "first_seen": top.get("first_seen_utc", ""),
        "last_seen": top.get("last_seen_utc", ""),
        "reporter": top.get("reporter", ""),
    }


def check_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)
    except Exception as e:
        return {"error": str(e)}

    def fmt_date(d):
        if isinstance(d, list):
            d = d[0]
        if isinstance(d, datetime):
            return d.strftime("%Y-%m-%d")
        return str(d) if d else None

    creation = fmt_date(w.creation_date)
    age_days = None
    if w.creation_date:
        cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        if isinstance(cd, datetime):
            age_days = (datetime.now() - cd.replace(tzinfo=None)).days

    return {
        "source": "WHOIS",
        "domain": domain,
        "registrar": w.registrar or "unknown",
        "creation_date": creation,
        "expiration_date": fmt_date(w.expiration_date),
        "updated_date": fmt_date(w.updated_date),
        "age_days": age_days,
        "country": w.country or "unknown",
        "org": w.org or "unknown",
        "name_servers": list(w.name_servers) if w.name_servers else [],
    }


# ─── Streamlit UI ────────────────────────────────────────────────────────────

st.set_page_config(page_title="Threat Intel Checker", page_icon="", layout="wide")

st.title("Threat Intel IOC Checker")
st.caption("Check IPs, domains, and URLs against multiple threat intel sources")

# Sidebar — API key status
with st.sidebar:
    st.header("API Status")
    for name, env_var in [
        ("VirusTotal", "VIRUSTOTAL_API_KEY"),
        ("AbuseIPDB", "ABUSEIPDB_API_KEY"),
        ("URLScan", "URLSCAN_API_KEY"),
        ("Hybrid Analysis", "HYBRID_ANALYSIS_API_KEY"),
        ("ThreatFox", "THREATFOX_API_KEY"),
    ]:
        if os.environ.get(env_var):
            st.success(f"{name}: Connected")
        else:
            st.error(f"{name}: Missing key")
    st.success("WHOIS: No key needed")

    st.divider()
    st.header("Services")
    run_whois = st.checkbox("WHOIS Lookup", value=True)
    run_vt = st.checkbox("VirusTotal", value=True)
    run_abuse = st.checkbox("AbuseIPDB", value=True)
    run_urlscan = st.checkbox("URLScan.io", value=True)
    run_hybrid = st.checkbox("Hybrid Analysis", value=True)
    run_threatfox = st.checkbox("ThreatFox", value=True)

    st.divider()
    st.caption("Free tier limits:")
    st.caption("VT: 4 req/min, 500/day")
    st.caption("AbuseIPDB: 1000/day")
    st.caption("URLScan: 2000/month")
    st.caption("Hybrid: 5 req/min, 200/hr")
    st.caption("ThreatFox: Free (fair use)")
    st.caption("WHOIS: No limit")

# Main input
ioc_input = st.text_area(
    "Enter IOCs (one per line)",
    placeholder="8.8.8.8\nmalware.wicar.org\nhttps://suspicious-site.com",
    height=120,
)

col1, col2 = st.columns([1, 5])
with col1:
    scan_button = st.button("Scan", type="primary")

if scan_button and ioc_input.strip():
    iocs = [line.strip() for line in ioc_input.strip().split("\n") if line.strip()]

    for raw_ioc in iocs:
        parsed = parse_ioc(raw_ioc)
        st.divider()
        st.subheader(f"Results: {raw_ioc}")
        if parsed["lookup"] != raw_ioc:
            st.caption(f"Domain extracted: **{parsed['lookup']}**")
        if parsed.get("resolved_ip") and parsed["type"] != "ip":
            st.caption(f"Resolved IP: **{parsed['resolved_ip']}**")

        # Collect all enabled results into a list, then render dynamically
        panels = []

        # WHOIS first — good jumping-off point for domain context
        if run_whois:
            if parsed["type"] == "ip":
                panels.append(("WHOIS", "info", "WHOIS lookup is for domains only"))
            else:
                with st.spinner("WHOIS lookup..."):
                    wh = check_whois(parsed["lookup"])
                panels.append(("WHOIS", "data", wh))

        # VirusTotal
        if run_vt:
            with st.spinner("Checking VirusTotal..."):
                vt = check_virustotal(parsed["lookup"])
            panels.append(("VirusTotal", "data", vt))

        # AbuseIPDB
        if run_abuse:
            abuse_ip = parsed["resolved_ip"]
            with st.spinner("Checking AbuseIPDB..."):
                if abuse_ip:
                    abuse = check_abuseipdb(abuse_ip)
                else:
                    abuse = {"skipped": True, "reason": "Could not resolve domain to IP"}
            panels.append(("AbuseIPDB", "data", abuse))

        # URLScan
        if run_urlscan:
            with st.spinner("Scanning with URLScan (15-60s)..."):
                uscan = check_urlscan(parsed["full_url"])
            panels.append(("URLScan.io", "data", uscan))

        # Hybrid Analysis
        if run_hybrid:
            with st.spinner("Checking Hybrid Analysis..."):
                ha = check_hybrid_analysis(parsed["lookup"], parsed["type"])
            panels.append(("Hybrid Analysis", "data", ha))

        # ThreatFox
        if run_threatfox:
            with st.spinner("Checking ThreatFox..."):
                tf = check_threatfox(parsed["lookup"])
            panels.append(("ThreatFox", "data", tf))

        # Render panels in rows of up to 3 columns, no blank gaps
        if not panels:
            st.info("No services selected. Enable services in the sidebar.")
        else:
            for row_start in range(0, len(panels), 3):
                row = panels[row_start : row_start + 3]
                cols = st.columns(len(row))
                for col, (name, ptype, pdata) in zip(cols, row):
                    with col:
                        st.markdown(f"**{name}**")
                        if ptype == "info":
                            st.info(pdata)
                        elif "error" in pdata:
                            st.error(pdata["error"])
                        elif "skipped" in pdata:
                            st.info(pdata["reason"])
                        elif name == "WHOIS":
                            age = pdata.get("age_days")
                            if age is not None and age < 30:
                                st.error(f"Newly registered: {age} days old")
                            elif age is not None and age < 365:
                                st.warning(f"Domain age: {age} days")
                            elif age is not None:
                                st.success(f"Domain age: {age} days ({age // 365} years)")
                            st.markdown(f"**Registrar:** {pdata.get('registrar', 'unknown')}")
                            st.markdown(f"**Created:** {pdata.get('creation_date', 'unknown')}")
                            st.markdown(f"**Expires:** {pdata.get('expiration_date', 'unknown')}")
                            st.markdown(f"**Updated:** {pdata.get('updated_date', 'unknown')}")
                            st.markdown(f"**Country:** {pdata.get('country', 'unknown')}")
                            st.markdown(f"**Org:** {pdata.get('org', 'unknown')}")
                            st.json(pdata)
                        elif name == "VirusTotal":
                            mal = pdata["malicious"]
                            total = pdata["total_engines"]
                            if mal > 0:
                                st.error(f"Malicious: {mal}/{total} engines")
                            else:
                                st.success(f"Clean: 0/{total} engines")
                            st.metric("Reputation", pdata["reputation"])
                            st.json(pdata)
                        elif name == "AbuseIPDB":
                            score = pdata["abuse_confidence"]
                            if score > 50:
                                st.error(f"Abuse Confidence: {score}%")
                            elif score > 0:
                                st.warning(f"Abuse Confidence: {score}%")
                            else:
                                st.success(f"Abuse Confidence: {score}%")
                            st.metric("Total Reports", pdata["total_reports"])
                            st.json(pdata)
                        elif name == "URLScan.io":
                            if pdata.get("malicious"):
                                st.error(f"Malicious (score: {pdata['score']})")
                            else:
                                st.success(f"Clean (score: {pdata['score']})")
                            if pdata.get("screenshot"):
                                st.image(pdata["screenshot"], caption="Page Screenshot")
                            if pdata.get("result_url"):
                                st.markdown(f"[Full Report]({pdata['result_url']})")
                            st.json(pdata)
                        elif name == "Hybrid Analysis":
                            total = pdata.get("total_reports", 0)
                            mal = pdata.get("malicious_reports", 0)
                            if total == 0:
                                st.info("No sandbox reports found")
                            elif mal > 0:
                                st.error(f"Malicious: {mal}/{total} reports")
                            else:
                                st.success(f"Clean: {total} reports, 0 malicious")
                            if pdata.get("threat_names"):
                                st.warning(f"Threats: {', '.join(pdata['threat_names'])}")
                            st.json(pdata)
                        elif name == "ThreatFox":
                            if pdata.get("status") == "not_found":
                                st.info("Not found in ThreatFox database")
                            else:
                                families = pdata.get("malware_families", [])
                                if families:
                                    st.error(f"Malware: {', '.join(families)}")
                                st.markdown(f"**Threat Type:** {', '.join(pdata.get('threat_types', []))}")
                                if pdata.get("tags"):
                                    st.markdown(f"**Tags:** {', '.join(pdata['tags'])}")
                                st.metric("Confidence", pdata.get("top_confidence", 0))
                            st.json(pdata)

        # Rate limit between IOCs
        if run_vt and len(iocs) > 1:
            time.sleep(15)

elif scan_button:
    st.warning("Enter at least one IOC to scan.")
