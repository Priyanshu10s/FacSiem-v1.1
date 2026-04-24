import argparse
import json
import re
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

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

def extract_features_from_entries(entries):
    req_count = len(entries)
    unique_urls = len({e['url'] for e in entries})
    error_count = sum(1 for e in entries if e['status'] >= 400)
    error_rate = error_count / req_count if req_count else 0.0
    times = sorted(e['time'] for e in entries)
    if len(times) <= 1:
        avg_gap = 9999.0
    else:
        gaps = [
            (times[i] - times[i - 1]).total_seconds()
            for i in range(1, len(times))
        ]
        avg_gap = sum(gaps) / len(gaps)
    sensitive_hits = sum(
        1 for e in entries
        if any(p in e['url'] for p in SENSITIVE_PATHS)
    )
    sqli_hits = sum(
        1 for e in entries
        for pat in SQLI_PATTERNS
        if re.search(pat, e['url'].lower())
    )
    return {
        "req_count": req_count,
        "unique_urls": unique_urls,
        "error_rate": error_rate,
        "avg_time_gap": avg_gap,
        "sensitive_hits": sensitive_hits,
        "sqli_hits": sqli_hits,
    }

def windowed_features_for_all_ips(entries_all, window_minutes=1):
    features = []
    window_delta = timedelta(minutes=window_minutes)
    entries_all.sort(key=lambda x: x["time"])
    ips = set(e["ip"] for e in entries_all)

    for ip in ips:
        ip_entries = [e for e in entries_all if e["ip"] == ip]
        for e in ip_entries:
            start = e["time"]
            win_entries = [
                x for x in ip_entries
                if start <= x["time"] < start + window_delta
            ]
            feat = extract_features_from_entries(win_entries)
            if feat:
                feat["ip"] = ip
                feat["start"] = start.isoformat()
                features.append(feat)

    return pd.DataFrame(features)

def load_model(path):
    path = Path(path)
    if not path.exists():
        raise SystemExit(f"Model file {path} not found. Train first using train_ml.py")
    obj = joblib.load(path)
    if isinstance(obj, tuple) and len(obj) == 2:
        model, cols = obj
    else:
        model = obj
        cols = [
            "req_count",
            "unique_urls",
            "error_rate",
            "avg_time_gap",
            "sensitive_hits",
            "sqli_hits",
        ]
    return model, cols

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, help="Log to analyze")
    parser.add_argument("--model", default="iforest_joblib.pkl", help="Trained model file")
    parser.add_argument("--window", type=int, default=1, help="Window minutes")
    parser.add_argument("--json-out", default="report_ml.json", help="Output report JSON")
    args = parser.parse_args()

    entries = []
    with open(args.log, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            p = parse_line(line)
            if p:
                entries.append(p)

    if not entries:
        print("No valid log entries found.")
        return

    df = windowed_features_for_all_ips(entries, window_minutes=args.window)
    if df.empty:
        print("No features created from log.")
        return

    model, cols = load_model(args.model)

    X = df[cols].copy()
    X["req_count"] = np.log1p(X["req_count"])
    X["unique_urls"] = np.log1p(X["unique_urls"])
    X["avg_time_gap"] = np.log1p(X["avg_time_gap"])
    X = X.fillna(0)

    scores = model.decision_function(X)
    preds = model.predict(X)

    df["score"] = scores
    df["pred"] = preds

    anomalies = df[df["pred"] == -1].sort_values("score")
    anomalies_list = anomalies[
        [
            "ip",
            "start",
            "req_count",
            "unique_urls",
            "error_rate",
            "avg_time_gap",
            "sensitive_hits",
            "sqli_hits",
            "score",
        ]
    ].to_dict(orient="records")

    report = {
        "n_windows": int(len(df)),
        "n_anomalies": int(len(anomalies_list)),
        "anomalies": anomalies_list,
    }

    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"Saved ML anomalies report to {args.json_out}")
    print(f"Total windows: {len(df)}, anomalies: {len(anomalies_list)}")

if __name__ == "__main__":
    main()
