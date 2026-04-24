import json
from pathlib import Path

import pandas as pd
import streamlit as st

REPORT_JSON = "report.json"

st.set_page_config(page_title="Mini SIEM Dashboard", layout="wide")

st.title("🛡️ Mini SIEM / IDS Dashboard")

if not Path(REPORT_JSON).exists():
    st.error(f"'{REPORT_JSON}' not found. Run mini_ids.py first to generate it.")
    st.stop()

with open(REPORT_JSON, "r", encoding="utf-8") as f:
    data = json.load(f)

# Top summary
log_path = data.get("log_path", "")
brute_thr = data.get("brute_force_threshold")
rate_thr = data.get("rate_threshold")
window_min = data.get("window_minutes")

st.sidebar.header("Config")
st.sidebar.write(f"**Log file:** `{log_path}`")
st.sidebar.write(f"**Brute-force threshold:** {brute_thr}")
st.sidebar.write(f"**Rate threshold:** {rate_thr} req / {window_min} min")

st.markdown(
    f"""
**Log:** `{log_path}`  
**Brute-force threshold:** `{brute_thr}`  
**Rate threshold:** `{rate_thr}` req / `{window_min}` min
"""
)

# Convert sections to DataFrames
brute_df = pd.DataFrame(data.get("brute_force", []))
sqli_df = pd.DataFrame(data.get("sqli", []))
sens_df = pd.DataFrame(data.get("sensitive_paths", []))
high_rate_ips = data.get("high_rate_ips", [])
high_df = pd.DataFrame([{"ip": ip} for ip in high_rate_ips])

col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Brute-force entries", len(brute_df))
with col2:
    st.metric("SQLi suspects", len(sqli_df))
with col3:
    st.metric("Sensitive path scanners", len(sens_df))

st.markdown("---")

# Brute-force section
st.subheader("🔐 Possible Brute-force Attempts")
if brute_df.empty:
    st.info("No brute-force attempts detected (above threshold).")
else:
    st.dataframe(brute_df)

    # Top IPs by count
    top_brute = (
        brute_df.groupby("ip")["count"]
        .sum()
        .sort_values(ascending=False)
        .reset_index()
    )
    st.markdown("**Top IPs by brute-force activity**")
    st.bar_chart(top_brute.set_index("ip"))

st.markdown("---")

# SQLi section
st.subheader("💉 SQL Injection Suspects")
if sqli_df.empty:
    st.info("No SQLi patterns detected.")
else:
    st.dataframe(sqli_df)
    st.markdown("**Top IPs by SQLi attempts**")
    st.bar_chart(sqli_df.set_index("ip"))

st.markdown("---")

# Sensitive path scanners
st.subheader("🚪 Sensitive Path Scanners")
if sens_df.empty:
    st.info("No hits on sensitive paths.")
else:
    st.dataframe(sens_df)
    st.markdown("**Top IPs scanning sensitive paths**")
    st.bar_chart(sens_df.set_index("ip"))

st.markdown("---")

# High-rate IPs
st.subheader("⚡ High Request Rate IPs")
if high_df.empty:
    st.info("No IP exceeded the rate threshold.")
else:
    st.dataframe(high_df)
st.markdown("---")

# 🤖 ML-based anomalies section
st.subheader("🤖 ML-based Anomalies (IsolationForest)")

ML_REPORT = "report_ml.json"

if Path(ML_REPORT).exists():
    with open(ML_REPORT, "r", encoding="utf-8") as f:
        ml_data = json.load(f)

    ml_df = pd.DataFrame(ml_data.get("anomalies", []))

    if ml_df.empty:
        st.info("No anomalies detected by ML model.")
    else:
        st.write(f"Total anomalous windows: {ml_data.get('n_anomalies', 0)}")
        st.dataframe(ml_df)

        if "ip" in ml_df.columns and "score" in ml_df.columns:
            st.markdown("**Average anomaly score per IP (lower = more suspicious)**")
            ip_scores = (
                ml_df.groupby("ip")["score"]
                .mean()
                .sort_values()
                .reset_index()
            )
            st.bar_chart(ip_scores.set_index("ip"))
else:
    st.info("ML report not found. Run mini_ids_ml.py to generate report_ml.json.")

