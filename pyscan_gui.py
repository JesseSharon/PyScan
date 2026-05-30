import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import queue
import os
import json
import logging
import time

import customtkinter as ctk
from watcher import start_watcher
from analyzer import analyze_file
from actions import ActionExecutor

# --------- Configuration ----------
with open("config.json") as f:
    config = json.load(f)

quarantine_folder = config["folders"]["quarantine"]
executor = ActionExecutor(config)
file_queue = queue.Queue()
processed_data = []  # store data for display

# --------- Logging setup to GUI ---------
class GuiLogger(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        self.filter_level = None

    def emit(self, record):
        if self.filter_level and record.levelno != self.filter_level:
            return
        msg = self.format(record)
        self.text_widget.configure(state='normal')
        # Color coding for logs
        if record.levelno == logging.INFO:
            tag = "INFO"
        elif record.levelno == logging.WARNING:
            tag = "WARNING"
        elif record.levelno == logging.ERROR:
            tag = "ERROR"
        else:
            tag = "OTHER"
        self.text_widget.insert(tk.END, msg + "\n", tag)
        self.text_widget.configure(state='disabled')
        self.text_widget.yview(tk.END)

    def set_filter(self, level):
        self.filter_level = level

# --------- File processing ----------
def process_file_gui(filepath, app):
    """
    Analyze file, execute actions, generate report, and update GUI instance `app`.
    """
    try:
        analysis = analyze_file(filepath)
        action_taken = executor.decide_action(filepath, analysis)
        executor.generate_report(filepath, analysis)
        processed_data.append((analysis.get("file_name", filepath), analysis.get("risk_level", "Unknown")))

        # Update GUI via methods on the app instance
        try:
            app.update_analysis(filepath, analysis, action_taken)
            app.update_reports_list()
            app.update_yara_tab(analysis)
        except Exception as gui_exc:
            logging.error(f"Error updating GUI for {filepath}: {gui_exc}")

    except Exception as e:
        logging.error(f"Error processing file {filepath}: {e}")

def file_queue_worker(app):
    processed_files = set()
    while True:
        filepath = file_queue.get()
        if filepath in processed_files:
            continue
        process_file_gui(filepath, app)
        processed_files.add(filepath)

# --------- GUI Application ----------
class PyScanGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")  # Default dark mode
        ctk.set_default_color_theme("dark-blue")

        self.title("PyScan GUI")
        self.geometry("1100x700")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Theme toggle button
        toggle_btn = ctk.CTkButton(self, text="Toggle Theme", command=self.toggle_theme)
        toggle_btn.pack(padx=10, pady=(10,0), anchor="ne")

        # Tab view
        self.tab_control = ctk.CTkTabview(self, width=1080, height=620)
        self.tab_control.pack(padx=10, pady=10)
        self.tab_control.add("Logs")
        self.tab_control.add("Analysis")
        self.tab_control.add("Reports")
        self.tab_control.add("YARA")   # NEW tab for detailed YARA output

        # --------- Logs tab ---------
        self.log_text = scrolledtext.ScrolledText(self.tab_control.tab("Logs"),
                                                  state='disabled', wrap='word',
                                                  font=("Consolas", 10), bg="#1E1E1E", fg="white")
        self.log_text.pack(expand=True, fill='both', padx=5, pady=5)
        self.log_text.tag_config("INFO", foreground="lightgreen")
        self.log_text.tag_config("WARNING", foreground="yellow")
        self.log_text.tag_config("ERROR", foreground="red")
        self.gui_handler = GuiLogger(self.log_text)
        self.gui_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logging.getLogger().addHandler(self.gui_handler)
        logging.getLogger().setLevel(logging.INFO)

        # Log filter buttons
        btn_frame = ctk.CTkFrame(self.tab_control.tab("Logs"))
        btn_frame.pack(fill='x', pady=5)
        ctk.CTkButton(btn_frame, text="All", command=lambda: self.set_log_filter(None), width=80).pack(side='left', padx=5)
        ctk.CTkButton(btn_frame, text="INFO", command=lambda: self.set_log_filter(logging.INFO), width=80).pack(side='left', padx=5)
        ctk.CTkButton(btn_frame, text="WARNING", command=lambda: self.set_log_filter(logging.WARNING), width=80).pack(side='left', padx=5)
        ctk.CTkButton(btn_frame, text="ERROR", command=lambda: self.set_log_filter(logging.ERROR), width=80).pack(side='left', padx=5)

        # --------- Analysis tab ---------
        self.analysis_text = scrolledtext.ScrolledText(self.tab_control.tab("Analysis"),
                                                       state='disabled', wrap='word',
                                                       font=("Consolas", 10), bg="#1E1E1E", fg="white")
        self.analysis_text.pack(expand=True, fill='both', padx=5, pady=5)
        self.analysis_text.tag_config("YARA", foreground="red")
        self.analysis_text.tag_config("HEADER", foreground="cyan")

        # --------- Reports tab ---------
        self.report_listbox = tk.Listbox(self.tab_control.tab("Reports"),
                                         font=("Consolas", 10), bg="#2E2E2E", fg="white")
        self.report_listbox.pack(expand=True, fill='both', padx=5, pady=5)
        self.report_listbox.bind("<Double-1>", self.open_report)
        self.update_reports_list()

        # --------- YARA tab ---------
        self.yara_text = scrolledtext.ScrolledText(self.tab_control.tab("YARA"),
                                                   state='disabled', wrap='word',
                                                   font=("Consolas", 10), bg="#1E1E1E", fg="white")
        self.yara_text.pack(expand=True, fill='both', padx=5, pady=5)
        # styles for severities
        self.yara_text.tag_config("HIGH", foreground="red", font=("Consolas", 10, "bold"))
        self.yara_text.tag_config("MEDIUM", foreground="orange")
        self.yara_text.tag_config("LOW", foreground="yellow")
        self.yara_text.tag_config("META", foreground="lightgray")

        self.current_theme = "dark"

    # --------- GUI methods ---------
    def toggle_theme(self):
        if self.current_theme == "dark":
            ctk.set_appearance_mode("light")
            self.log_text.config(bg="white", fg="black")
            self.analysis_text.config(bg="white", fg="black")
            self.report_listbox.config(bg="white", fg="black")
            self.yara_text.config(bg="white", fg="black")
            self.current_theme = "light"
        else:
            ctk.set_appearance_mode("dark")
            self.log_text.config(bg="#1E1E1E", fg="white")
            self.analysis_text.config(bg="#1E1E1E", fg="white")
            self.report_listbox.config(bg="#2E2E2E", fg="white")
            self.yara_text.config(bg="#1E1E1E", fg="white")
            self.current_theme = "dark"

    def update_analysis(self, filepath, analysis, action):
        self.analysis_text.configure(state='normal')
        self.analysis_text.insert(tk.END, f"\nFile: {filepath}\n", "HEADER")
        self.analysis_text.insert(tk.END, f"Action Taken: {action}\n")
        for k, v in analysis.items():
            # keep YARA details on the separate tab
            if k == "yara":
                if v:
                    self.analysis_text.insert(tk.END, f"YARA matches: {len(v)} (see YARA tab)\n", "YARA")
                else:
                    self.analysis_text.insert(tk.END, "YARA matches: 0\n")
                continue
            self.analysis_text.insert(tk.END, f"{k}: {v}\n")
        self.analysis_text.insert(tk.END, "-"*80 + "\n")
        self.analysis_text.configure(state='disabled')
        self.analysis_text.yview(tk.END)

    def update_reports_list(self):
        self.report_listbox.delete(0, tk.END)
        reports_dir = config["folders"]["reports"]
        if not os.path.isdir(reports_dir):
            os.makedirs(reports_dir, exist_ok=True)
        for file in os.listdir(reports_dir):
            if file.endswith("_report.json"):
                self.report_listbox.insert(tk.END, file)

    def open_report(self, event):
        selection = self.report_listbox.curselection()
        if not selection:
            return
        report_file = self.report_listbox.get(selection[0])
        path = os.path.join(config["folders"]["reports"], report_file)
        with open(path) as f:
            content = json.load(f)
        top = ctk.CTkToplevel(self)
        top.title(report_file)
        txt = scrolledtext.ScrolledText(top, width=100, height=30,
                                       bg="#1E1E1E" if self.current_theme=="dark" else "white",
                                       fg="white" if self.current_theme=="dark" else "black")
        txt.pack(expand=True, fill='both')
        txt.insert(tk.END, json.dumps(content, indent=4))
        txt.configure(state='disabled')

    def set_log_filter(self, level):
        self.gui_handler.set_filter(level)
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        log_path = config["logging"].get("log_file", "analysis_actions.log")
        if os.path.exists(log_path):
            with open(log_path, "r") as f:
                for line in f:
                    if level is None:
                        self.log_text.insert(tk.END, line)
                    elif f"[{logging.getLevelName(level)}]" in line:
                        self.log_text.insert(tk.END, line)
        self.log_text.configure(state='disabled')

    def update_yara_tab(self, analysis):
        """
        Append YARA matches for a processed file to the YARA tab.
        Expects analysis["yara"] to be a list of dicts:
        {"rule_name": "...", "severity": "HIGH|MEDIUM|LOW", "timestamp": "ISOUTC"}
        """
        yara_matches = analysis.get("yara", [])
        self.yara_text.configure(state='normal')
        self.yara_text.insert(tk.END, f"\nFile: {analysis.get('file_name')}  ({analysis.get('file_path')})\n", "META")

        if not yara_matches:
            self.yara_text.insert(tk.END, "No YARA rules matched.\n", "LOW")
        else:
            for m in yara_matches:
                # handle possible variations robustly
                rule = m.get("rule_name") or m.get("rule") or "unknown"
                severity = (m.get("severity") or m.get("meta", {}).get("severity") or "UNKNOWN").upper()
                ts = m.get("timestamp") or m.get("timestamp_utc") or "N/A"

                tag = "MEDIUM"
                if severity == "HIGH":
                    tag = "HIGH"
                elif severity == "LOW":
                    tag = "LOW"
                elif severity == "UNKNOWN":
                    tag = "META"

                self.yara_text.insert(tk.END, f"Rule: {rule}\n", tag)
                self.yara_text.insert(tk.END, f"  Severity: {severity}  |  Time(UTC): {ts}\n", "META")
                # optional: show tags / matched string ids if present
                if m.get("tags"):
                    self.yara_text.insert(tk.END, f"  Tags: {m.get('tags')}\n")
                if m.get("matched_strings"):
                    self.yara_text.insert(tk.END, f"  Matched strings: {m.get('matched_strings')}\n")
                self.yara_text.insert(tk.END, "-"*60 + "\n")

        self.yara_text.configure(state='disabled')
        self.yara_text.yview(tk.END)

    def on_close(self):
        self.destroy()
        os._exit(0)

# --------- Start watcher thread (does not require app instance) ----------
watcher_thread = threading.Thread(target=start_watcher, args=(quarantine_folder, file_queue), daemon=True)
watcher_thread.start()

# --------- Create GUI instance ----------
app = PyScanGUI()

# --------- Start processor thread (needs app instance) ----------
processor_thread = threading.Thread(target=file_queue_worker, args=(app,), daemon=True)
processor_thread.start()

# --------- Run GUI ----------
app.mainloop()
