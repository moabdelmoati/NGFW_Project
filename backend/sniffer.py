"""
sniffer.py - simple sniffer simulator / poster to backend
- modes: SIMULATE (default) or LIVE (not implemented here)
- robust retry/backoff, saves unsent flows to disk for later resend
"""

import time
import json
import random
import logging
from pathlib import Path
from typing import Dict, Any, List

import requests
from requests.exceptions import ConnectionError, Timeout, RequestException

# CONFIG
INGEST_URL = "http://127.0.0.1:5000/api/ingest-enhanced"  # Use enhanced ingest for full NGFW detection
MODE = "SIMULATE"    # set to "LIVE" if you integrate with scapy/pyshark later
SIMULATE_INTERVAL = 0.5
UNSENT_FILE = Path("unsent_flows.jsonl")
MAX_RETRIES = 5
RETRY_BASE = 0.5
MAX_BACKOFF = 16.0

# logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s:%(name)s: %(message)s")
log = logging.getLogger("sniffer")


def simulate_flow() -> Dict[str, Any]:
    srcs = ["192.168.1.4", "192.168.1.8", "10.0.0.5", "172.16.0.10"]
    dsts = ["8.8.8.8", "104.29.146.192", "104.46.162.225"]
    proto = random.choice(["TCP", "UDP"])
    # Generate realistic flow duration (in seconds)
    flow_duration = random.uniform(0.1, 30.0)
    # Generate realistic packet counts
    tot_fwd_pkts = random.randint(1, 1000)
    tot_bwd_pkts = random.randint(1, 500)
    
    # Occasionally add suspicious URLs to test NGFW detection
    url = None
    if random.random() < 0.15:  # 15% chance of suspicious URL
        suspicious_urls = [
            "http://go.ogle.com/login",  # Typosquatting
            "http://example.com/../../../etc/passwd",  # Path traversal
            "http://malicious.com/union select * from users",  # SQL injection
            "http://phishing-site.cc/login",  # Suspicious domain
            "http://bic-wswhatsapp.com/verify",  # Malicious pattern
            "http://192.168.1.1/admin?cmd=cat /etc/passwd",  # Command injection
        ]
        url = random.choice(suspicious_urls)
    
    flow = {
        "src_ip": random.choice(srcs),
        "dst_ip": random.choice(dsts),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([53, 80, 443, 19336]),
        "protocol": proto,
        "pkt_hash": f"live-{random.randint(1000000000, 9999999999)}",
        "flow_duration": round(flow_duration, 2),
        "tot_fwd_pkts": tot_fwd_pkts,
        "tot_bwd_pkts": tot_bwd_pkts,
        "totlen_fwd_pkts": tot_fwd_pkts * random.randint(64, 1500),
        "totlen_bwd_pkts": tot_bwd_pkts * random.randint(64, 1500),
    }
    
    if url:
        flow["url"] = url
    
    return flow

def save_unsent(flow: Dict[str, Any]):
    with UNSENT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(flow, ensure_ascii=False) + "\n")

def load_unsent() -> List[Dict[str, Any]]:
    if not UNSENT_FILE.exists():
        return []
    out = []
    with UNSENT_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out

def clear_unsent():
    try:
        if UNSENT_FILE.exists():
            UNSENT_FILE.unlink()
    except Exception:
        pass

def post_flow(flow: Dict[str, Any]) -> bool:
    attempt = 0
    backoff = RETRY_BASE
    while attempt < MAX_RETRIES:
        try:
            r = requests.post(INGEST_URL, json=flow, timeout=3)
            if r.status_code in (200, 201):
                log.info("POST %s -> %s", INGEST_URL, r.status_code)
                return True
            else:
                log.warning("POST returned %s: %s", r.status_code, r.text)
                if 400 <= r.status_code < 500:
                    # client error -> don't retry
                    return False
        except (ConnectionError, Timeout) as e:
            log.warning("Attempt %d failed: %s", attempt + 1, e)
        except RequestException as e:
            log.error("RequestException: %s", e)
        attempt += 1
        time.sleep(min(backoff, MAX_BACKOFF))
        backoff *= 2
    log.warning("Failed to send flow after %d attempts; saving.", MAX_RETRIES)
    save_unsent(flow)
    return False

def resend_unsent():
    unsent = load_unsent()
    if not unsent:
        return
    log.info("Retrying %d unsent flows", len(unsent))
    remaining = []
    for f in unsent:
        ok = post_flow(f)
        if not ok:
            remaining.append(f)
    if remaining:
        with UNSENT_FILE.open("w", encoding="utf-8") as fh:
            for f in remaining:
                fh.write(json.dumps(f, ensure_ascii=False) + "\n")
    else:
        clear_unsent()

def simulate_loop(interval: float = SIMULATE_INTERVAL):
    try:
        while True:
            flow = simulate_flow()
            log.info("Captured flow: %s", flow)
            ok = post_flow(flow)
            # occasionally attempt resend
            if random.random() < 0.2:
                resend_unsent()
            time.sleep(interval)
    except KeyboardInterrupt:
        log.info("Stopping (KeyboardInterrupt). Attempting to resend unsent on exit...")
        resend_unsent()

if __name__ == "__main__":
    log.info("NGFW Sniffer starting. MODE=%s, INGEST=%s", MODE, INGEST_URL)
    # try resending previous unsent first
    resend_unsent()
    if MODE == "SIMULATE":
        simulate_loop()
    else:
        log.info("LIVE mode not implemented in this snippet.")
