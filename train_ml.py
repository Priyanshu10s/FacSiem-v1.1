import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# --- Config: reuse same patterns as IDS ---
import re
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" '
    r'(?P<status>\d{3}) \S+ "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'
)
SQLI_PATTERNS = [r"(\bor\b|\band\b)\s+1=1", r"union\s+select", r"sleep\(", r"information_schema", r"order\s+by\s+\d+"]
SENSITIVE_PATHS = ["/admin", "/login", "/wp-login", "/phpmyadmin", "/.git", "/server-status"]
TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

def parse_line(line):
    m = LOG_PATTERN.match(line)
    if not m:
        return None
    d = m.groupdict()
    try:
        d["status"] = int(d["status"])
        d["time"] = datetime.strptime(d["time"], TIME_FORMAT)
    except Exception:
        return None
    return d

def extract_features_from_window(entries):
    # entries: list of parsed dicts for a single IP within a window
    if not entries:
        return None
    req_count = len(entries)
    unique_urls = len({e['url'] for e in entries})
    error_count = sum(1 for e in entries if e['status'] >= 400)
    error_rate = error_count / req_count
    times = sorted(e['time'] for e in entries)
    if len(times) <= 1:
        avg_gap = 9999.0
    else:
        gaps = [(times[i] - times[i-1]).total_seconds() for i in range(1, len(times))]
        avg_gap = sum(gaps)/len(gaps)
    sensitive_hits = sum(1 for e in entries if any(p in e['url'] for p in SENSITIVE_PATHS))
    sqli_hits = sum(1 for e in entries for pat in SQLI_PATTERNS if re.search(pat, e['url'].lower()))
    return {
        "req_count": req_count,
        "unique_urls": unique_urls,
        "error_rate": error_rate,
        "avg_time_gap": avg_gap,
        "sensitive_hits": sensitive_hits,
        "sqli_hits": sqli_hits,
    }

def sliding_window_features(log_path, window_minutes=1):
    # group entries by IP and by window-start timestamp (rounded)
    ip_times = defaultdict(list)
    entries_all = []
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parse_line(line)
            if not parsed:
                continue
            entries_all.append(parsed)
    # sort global by time
    entries_all.sort(key=lambda x: x['time'])
    # build windows per IP
    features = []
    window_delta = timedelta(minutes=window_minutes)
    for ip in {e['ip'] for e in entries_all}:
        ip_entries = [e for e in entries_all if e['ip'] == ip]
        if not ip_entries:
            continue
        # sliding windows anchored at each entry time
        for i, e in enumerate(ip_entries):
            start = e['time']
            window_entries = [x for x in ip_entries if start <= x['time'] < start + window_delta]
            feat = extract_features_from_window(window_entries)
            if feat:
                feat['ip'] = ip
                features.append(feat)
    return pd.DataFrame(features)

def train(log_path, model_out, window_minutes=1, contamination=0.01):
    print("Extracting features from", log_path)
    df = sliding_window_features(log_path, window_minutes=window_minutes)
    if df.empty:
        raise SystemExit("No features extracted. Check log format or log content.")
    X = df[["req_count","unique_urls","error_rate","avg_time_gap","sensitive_hits","sqli_hits"]].fillna(0)
    # scale features lightly (IsolationForest is less sensitive to scaling but it's okay)
    # use log transform for req_count and unique_urls to reduce skew
    X = X.copy()
    X["req_count"] = np.log1p(X["req_count"])
    X["unique_urls"] = np.log1p(X["unique_urls"])
    X["avg_time_gap"] = np.log1p(X["avg_time_gap"])
    # fit model
    print("Training IsolationForest...")
    iso = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    iso.fit(X)
    joblib.dump((iso, X.columns.tolist()), model_out)
    print("Saved model to", model_out)
    # Save a small sample stats for reference
    stats = {
        "n_samples": int(len(X)),
        "feature_means": X.mean().to_dict(),
        "feature_std": X.std().to_dict(),
    }
    with open(Path(model_out).with_suffix(".meta.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, default=float)
    print("Training complete. Stats saved.")

if __name__ == "__main__":
    from collections import defaultdict
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, help="Baseline log file (normal traffic)")
    parser.add_argument("--out", default="iforest_joblib.pkl", help="Output model file")
    parser.add_argument("--window", type=int, default=1, help="Window minutes for features")
    parser.add_argument("--contamination", type=float, default=0.01, help="Expected fraction of anomalies in baseline")
    args = parser.parse_args()
    train(args.log, args.out, window_minutes=args.window, contamination=args.contamination)
