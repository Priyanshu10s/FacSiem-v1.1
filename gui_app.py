import os
import sys
import json
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

APP_TITLE = "Mini SIEM / IDS GUI"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON_CMD = sys.executable  # current python exe (better than plain "python")

def run_subprocess(args):
    try:
        result = subprocess.run(
            args,
            cwd=SCRIPT_DIR,
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)

def browse_log():
    path = filedialog.askopenfilename(
        title="Select access.log file",
        filetypes=[("Log files", "*.log *.txt *.*"), ("All files", "*.*")]
    )
    if path:
        log_path_var.set(path)

def run_ids():
    log_path = log_path_var.get().strip()
    if not log_path:
        messagebox.showwarning(APP_TITLE, "Please select a log file first.")
        return

    brute = brute_var.get().strip() or "10"
    rate = rate_var.get().strip() or "100"
    window = window_var.get().strip() or "1"

    # build command
    cmd = [
        PYTHON_CMD,
        "mini_ids.py",
        "--log", log_path,
        "--brute-threshold", brute,
        "--rate-threshold", rate,
        "--window-minutes", window,
        "--json-out", "report.json",
    ]

    output_box.insert(tk.END, f"\n[+] Running IDS:\n{' '.join(cmd)}\n")
    output_box.see(tk.END)

    code, out, err = run_subprocess(cmd)

    if out:
        output_box.insert(tk.END, f"{out}\n")
    if err:
        output_box.insert(tk.END, f"[STDERR]\n{err}\n")

    if code != 0:
        messagebox.showerror(APP_TITLE, "IDS run failed. Check output.")
        return

    # load report.json
    report_path = os.path.join(SCRIPT_DIR, "report.json")
    if not os.path.exists(report_path):
        output_box.insert(tk.END, "report.json not found after IDS run.\n")
        return

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        output_box.insert(tk.END, f"Failed to read report.json: {e}\n")
        return

    brute_count = len(data.get("brute_force", []))
    sqli_count = len(data.get("sqli", []))
    sens_count = len(data.get("sensitive_paths", []))
    high_count = len(data.get("high_rate_ips", []))

    summary = (
        "\n[IDS Summary]\n"
        f"Brute-force entries: {brute_count}\n"
        f"SQLi suspects: {sqli_count}\n"
        f"Sensitive path scanners: {sens_count}\n"
        f"High-rate IPs: {high_count}\n"
    )
    output_box.insert(tk.END, summary)
    output_box.see(tk.END)

def run_ml():
    log_path = log_path_var.get().strip()
    if not log_path:
        messagebox.showwarning(APP_TITLE, "Please select a log file first.")
        return

    model_path = os.path.join(SCRIPT_DIR, "iforest_joblib.pkl")
    if not os.path.exists(model_path):
        messagebox.showerror(APP_TITLE, "ML model 'iforest_joblib.pkl' not found. Train it first with train_ml.py.")
        return

    window = ml_window_var.get().strip() or "1"

    cmd = [
        PYTHON_CMD,
        "mini_ids_ml.py",
        "--log", log_path,
        "--model", model_path,
        "--window", window,
        "--json-out", "report_ml.json",
    ]

    output_box.insert(tk.END, f"\n[+] Running ML Anomaly Detection:\n{' '.join(cmd)}\n")
    output_box.see(tk.END)

    code, out, err = run_subprocess(cmd)

    if out:
        output_box.insert(tk.END, f"{out}\n")
    if err:
        output_box.insert(tk.END, f"[STDERR]\n{err}\n")

    if code != 0:
        messagebox.showerror(APP_TITLE, "ML analysis failed. Check output.")
        return

    ml_report_path = os.path.join(SCRIPT_DIR, "report_ml.json")
    if not os.path.exists(ml_report_path):
        output_box.insert(tk.END, "report_ml.json not found after ML run.\n")
        return

    try:
        with open(ml_report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        output_box.insert(tk.END, f"Failed to read report_ml.json: {e}\n")
        return

    n_windows = data.get("n_windows", 0)
    n_anom = data.get("n_anomalies", 0)

    summary = (
        "\n[ML Summary]\n"
        f"Total windows: {n_windows}\n"
        f"Anomalous windows: {n_anom}\n"
    )
    output_box.insert(tk.END, summary)
    output_box.see(tk.END)

def open_dashboard():
    # streamlit run dashboard.py
    cmd = ["streamlit", "run", "dashboard.py"]
    output_box.insert(tk.END, f"\n[+] Launching Streamlit dashboard:\n{' '.join(cmd)}\n")
    output_box.see(tk.END)

    try:
        subprocess.Popen(cmd, cwd=SCRIPT_DIR)
    except Exception as e:
        messagebox.showerror(APP_TITLE, f"Failed to launch dashboard: {e}")

def clear_output():
    output_box.delete(1.0, tk.END)

# ---------- GUI layout ----------

root = tk.Tk()
root.title(APP_TITLE)
root.geometry("900x600")

# Top: Log selection
frame_top = tk.Frame(root)
frame_top.pack(fill="x", padx=10, pady=5)

tk.Label(frame_top, text="Log file:").pack(side="left")

log_path_var = tk.StringVar()
log_entry = tk.Entry(frame_top, textvariable=log_path_var, width=60)
log_entry.pack(side="left", padx=5)

browse_btn = tk.Button(frame_top, text="Browse", command=browse_log)
browse_btn.pack(side="left", padx=5)

# IDS config frame
frame_ids = tk.LabelFrame(root, text="Rule-based IDS Settings")
frame_ids.pack(fill="x", padx=10, pady=5)

tk.Label(frame_ids, text="Brute threshold:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
brute_var = tk.StringVar(value="10")
tk.Entry(frame_ids, textvariable=brute_var, width=8).grid(row=0, column=1, padx=5, pady=2)

tk.Label(frame_ids, text="Rate threshold (req):").grid(row=0, column=2, sticky="w", padx=5, pady=2)
rate_var = tk.StringVar(value="100")
tk.Entry(frame_ids, textvariable=rate_var, width=8).grid(row=0, column=3, padx=5, pady=2)

tk.Label(frame_ids, text="Window (minutes):").grid(row=0, column=4, sticky="w", padx=5, pady=2)
window_var = tk.StringVar(value="1")
tk.Entry(frame_ids, textvariable=window_var, width=8).grid(row=0, column=5, padx=5, pady=2)

run_ids_btn = tk.Button(frame_ids, text="Run IDS", command=run_ids)
run_ids_btn.grid(row=0, column=6, padx=10, pady=2)

# ML config frame
frame_ml = tk.LabelFrame(root, text="ML Anomaly Detection (IsolationForest)")
frame_ml.pack(fill="x", padx=10, pady=5)

tk.Label(frame_ml, text="Window (minutes):").grid(row=0, column=0, sticky="w", padx=5, pady=2)
ml_window_var = tk.StringVar(value="1")
tk.Entry(frame_ml, textvariable=ml_window_var, width=8).grid(row=0, column=1, padx=5, pady=2)

run_ml_btn = tk.Button(frame_ml, text="Run ML Analysis", command=run_ml)
run_ml_btn.grid(row=0, column=2, padx=10, pady=2)

dash_btn = tk.Button(frame_ml, text="Open Dashboard", command=open_dashboard)
dash_btn.grid(row=0, column=3, padx=10, pady=2)

# Output area
frame_out = tk.LabelFrame(root, text="Output")
frame_out.pack(fill="both", expand=True, padx=10, pady=5)

output_box = scrolledtext.ScrolledText(frame_out, wrap=tk.WORD)
output_box.pack(fill="both", expand=True)

clear_btn = tk.Button(root, text="Clear Output", command=clear_output)
clear_btn.pack(pady=5)

output_box.insert(tk.END, "Mini SIEM / IDS GUI ready.\nSelect a log file, then click 'Run IDS' or 'Run ML Analysis'.\n")

root.mainloop()
