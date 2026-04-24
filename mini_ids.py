import re
import json
import argparse
from collections import defaultdict, Counter
from datetime import datetime, timedelta

# ---------- TELEGRAM SETTINGS (optional) ----------
# Agar Telegram alerts chahiye to inko fill karo
TELEGRAM_BOT_TOKEN = ""   # e.g. "123456789:ABCDEF..."
TELEGRAM_CHAT_ID = ""     # e.g. "123456789"

def send_telegram_message(text, enabled=False):
    if not enabled:
        return
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[ALERT] Telegram config missing. Skipping send.")
        return
    try:
        import requests
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {"chat_id": TELEGRAM_CHAT_ID, "text": text}
        requests.post(url, data=data, timeout=5)
    except Exception as e:
        print("[ALERT] Failed to send Telegram message:", e)

# ---------- LOG PARSING CONFIG ----------

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" '
    r'(?P<status>\d{3}) \S+ "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'
)

SQLI_PATTERNS = [
    r"(\bor\b|\band\b)\s+1=1",
    r"union\s+select",
    r"sleep\(",
    r"information_schema",
    r"order\s+by\s+\d+",
]

SENSITIVE_PATHS = [
    "/admin", "/login", "/wp-login", "/phpmyadmin", "/.git", "/server-status"
]

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# ---------- CORE HELPERS ----------

def parse_log_line(line):
    m = LOG_PATTERN.match(line)
    if not m:
        return None
    data = m.groupdict()
    try:
        data["status"] = int(data["status"])
        data["time"] = datetime.strptime(data["time"], TIME_FORMAT)
    except Exception:
        return None
    return data

def is_sqli(url):
    url_l = url.lower()
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, url_l):
            return True
    return False

def is_sensitive_path(url):
    return any(p in url for p in SENSITIVE_PATHS)

def analyze_log(path):
    brute_force_counter = defaultdict(int)   # (ip,url) -> count
    sqli_counter = Counter()                 # ip -> count
    sensitive_hits = Counter()               # ip -> count
    ip_requests = defaultdict(list)          # ip -> [times]

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            entry = parse_log_line(line)
            if not entry:
                continue

            ip = entry["ip"]
            url = entry["url"]
            status = entry["status"]
            t = entry["time"]

            ip_requests[ip].append(t)

            # brute-force-ish errors
            if status in (401, 403, 404):
                key = (ip, url)
                brute_force_counter[key] += 1

            if is_sqli(url):
                sqli_counter[ip] += 1

            if is_sensitive_path(url):
                sensitive_hits[ip] += 1

    return brute_force_counter, sqli_counter, sensitive_hits, ip_requests

def detect_high_rate(ip_requests, threshold=100, window_minutes=1):
    high_rate_ips = []
    window = timedelta(minutes=window_minutes)

    for ip, times in ip_requests.items():
        times = sorted(times)
        start = 0
        for i in range(len(times)):
            while times[i] - times[start] > window:
                start += 1
            if i - start + 1 >= threshold:
                high_rate_ips.append(ip)
                break
    return high_rate_ips

# ---------- MAIN ----------

def main():
    parser = argparse.ArgumentParser(description="Mini IDS / Log Analyzer")
    parser.add_argument("--log", default="access.log", help="Path to access log file")
    parser.add_argument("--brute-threshold", type=int, default=10,
                        help="Min errors (401/403/404) per IP+URL to flag brute-force")
    parser.add_argument("--rate-threshold", type=int, default=100,
                        help="Min requests per IP per window to flag high-rate")
    parser.add_argument("--window-minutes", type=int, default=1,
                        help="Window (minutes) for high-rate detection")
    parser.add_argument("--json-out", default="report.json",
                        help="Path to JSON report file (set empty to disable)")
    parser.add_argument("--alerts", action="store_true",
                        help="Enable Telegram alerts (configure token + chat id in file)")
    args = parser.parse_args()

    log_path = args.log
    brute_threshold = args.brute_threshold
    rate_threshold = args.rate_threshold
    window_minutes = args.window_minutes

    print(f"Analyzing log: {log_path}")
    brute_force_counter, sqli_counter, sensitive_hits, ip_requests = analyze_log(log_path)

    # ----- Console output -----

    print(f"\n=== Possible brute-force attempts (IP, URL, count >= {brute_threshold}) ===")
    brute_events = []
    for (ip, url), count in brute_force_counter.items():
        if count >= brute_threshold:
            print(f"{ip} -> {url} : {count} suspicious responses")
            brute_events.append({"ip": ip, "url": url, "count": count})

    print("\n=== SQL injection suspects (IP: count) ===")
    sqli_events = []
    for ip, count in sqli_counter.most_common():
        print(f"{ip} : {count} possible SQLi attempts")
        sqli_events.append({"ip": ip, "count": count})

    print("\n=== Sensitive path scanners (IP: count) ===")
    sensitive_events = []
    for ip, count in sensitive_hits.most_common():
        print(f"{ip} : {count} hits on sensitive paths")
        sensitive_events.append({"ip": ip, "count": count})

    print(f"\n=== High request rate IPs (>= {rate_threshold} req/{window_minutes} min) ===")
    high_rate_ips = detect_high_rate(ip_requests,
                                     threshold=rate_threshold,
                                     window_minutes=window_minutes)
    for ip in high_rate_ips:
        print(ip)

    # ----- JSON report -----

    if args.json_out:
        report = {
            "log_path": log_path,
            "brute_force_threshold": brute_threshold,
            "rate_threshold": rate_threshold,
            "window_minutes": window_minutes,
            "brute_force": brute_events,
            "sqli": sqli_events,
            "sensitive_paths": sensitive_events,
            "high_rate_ips": high_rate_ips,
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nSaved JSON report to {args.json_out}")

    # ----- Alerts -----

    if args.alerts:
        # Brute-force alerts
        for e in brute_events:
            msg = f"BRUTE-FORCE ALERT: {e['ip']} -> {e['url']} ({e['count']} errors)"
            send_telegram_message(msg, enabled=True)

        # SQLi alerts
        for e in sqli_events:
            msg = f"SQLi ALERT: {e['ip']} ({e['count']} possible attempts)"
            send_telegram_message(msg, enabled=True)

        # High-rate alerts
        for ip in high_rate_ips:
            msg = f"HIGH-RATE ALERT: {ip} exceeded {rate_threshold} req/{window_minutes} min"
            send_telegram_message(msg, enabled=True)

if __name__ == "__main__":
    main()
