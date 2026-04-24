import json
from pathlib import Path

REPORT_JSON = "report.json"
REPORT_HTML = "report.html"

def generate_html(data):
    def section(title, rows, cols):
        html = f"<h2>{title}</h2>"
        if not rows:
            html += "<p><i>No data</i></p>"
            return html
        html += "<table border='1' cellpadding='6' cellspacing='0'>"
        html += "<tr>" + "".join(f"<th>{c}</th>" for c in cols) + "</tr>"
        for r in rows:
            html += "<tr>" + "".join(f"<td>{r.get(c, '')}</td>" for c in cols) + "</tr>"
        html += "</table>"
        return html

    brute_rows = data.get("brute_force", [])
    sqli_rows = data.get("sqli", [])
    sensitive_rows = data.get("sensitive_paths", [])
    high_rate_ips = data.get("high_rate_ips", [])

    high_rate_rows = [{"ip": ip} for ip in high_rate_ips]

    html = f"""
    <html>
    <head>
        <title>Mini SIEM Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            table {{ border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ padding: 6px 10px; }}
            th {{ background: #eee; }}
        </style>
    </head>
    <body>
        <h1>Mini SIEM / IDS Report</h1>
        <p><b>Log file:</b> {data.get("log_path", "")}</p>
        <p><b>Brute-force threshold:</b> {data.get("brute_force_threshold")}</p>
        <p><b>Rate threshold:</b> {data.get("rate_threshold")} req/{data.get("window_minutes")} min</p>

        {section("Brute-force Attempts", brute_rows, ["ip", "url", "count"])}
        {section("SQL Injection Suspects", sqli_rows, ["ip", "count"])}
        {section("Sensitive Path Scanners", sensitive_rows, ["ip", "count"])}
        {section("High Request Rate IPs", high_rate_rows, ["ip"])}
    </body>
    </html>
    """
    return html

def main():
    if not Path(REPORT_JSON).exists():
        print(f"{REPORT_JSON} not found. Run mini_ids.py first.")
        return

    with open(REPORT_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    html = generate_html(data)

    with open(REPORT_HTML, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"HTML report saved to {REPORT_HTML}")

if __name__ == "__main__":
    main()
