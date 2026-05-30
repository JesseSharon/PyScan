import queue
import threading
import logging
import os
import time
import random
import json
import subprocess
import psutil
import csv
from pyfiglet import Figlet
from colorama import init as colorama_init, Fore, Style

from watcher import start_watcher
from analyzer import analyze_file
from actions import ActionExecutor

colorama_init(autoreset=True)

# --------- Logging Setup ----------
logging.basicConfig(
    filename="analysis_actions.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# --------- Fancy Banner ----------
def fancy_banner():
    fonts = [
        "slant", "big", "standard", "banner3-D", "starwars", "isometric1", "isometric2",
        "isometric3", "isometric4", "smslant", "smshadow", "speed", "doom", "graffiti", "rectangles",
        "univers", "block", "cyberlarge", "cybermedium", "digital", "3-d", "3x5", "epic", "poison",
        "fuzzy", "rounded", "colossal", "larry3d", "puffy", "roman", "serifcap", "ogre", "avatar",
        "acrobatic", "bell", "bulbhead", "chunky", "nancyj", "pepper", "lean", "rounded", "slscript",
        "swamp_land", "thick", "twopoint", "wavy", "xhelvi", "zigzag"
    ]
    selected_font = random.choice(fonts)
    f = Figlet(font=selected_font)
    print("\n" + f.renderText('PyScan'))
    print("🔍 Real-Time Malware Analysis in Quarantine Folders\n")

# --------- File Processing ----------
def process_file(filepath, executor, config):
    logging.info(f"Processing file: {filepath}")
    print(f"\n[+] New file detected: {filepath}")

    wait_time = 0
    while not os.path.exists(filepath) and wait_time < 10:
        time.sleep(0.5)
        wait_time += 0.5

    if not os.path.exists(filepath):
        logging.warning(f"File not found after waiting: {filepath}")
        return

    time.sleep(5)  # let the file finish writing

    analysis = analyze_file(filepath)
    if "error" in analysis:
        logging.error(f"Error analyzing file {filepath}: {analysis['error']}")
        print(f"[!] Error analyzing file: {analysis['error']}")
        return

    print("=== Analysis Results ===")
    for k, v in analysis.items():
        # Print compactly but include yara in dedicated block
        if k == "yara_matches":
            continue
        print(f"{k}: {v}")

    # --- Print YARA section ---
    yara_matches = analysis.get("yara_matches", [])
    if yara_matches:
        print("\n" + Fore.RED + "=== YARA MATCHES ===" + Style.RESET_ALL)
        for m in yara_matches:
            if m.get("error"):
                print(Fore.YELLOW + f"YARA error: {m['error']}")
                continue
            rule = m.get("rule", "unknown")
            severity = m.get("severity", "unknown")
            tags = m.get("tags", [])
            timestamp = m.get("timestamp_utc", "")
            matched_strings = m.get("matched_strings", [])
            print(Fore.RED + f"Rule: {rule} " + Fore.RESET + f" | Severity: {severity} | Time(UTC): {timestamp}")
            if tags:
                print(f"  tags: {tags}")
            if matched_strings:
                print(f"  matched strings: {matched_strings}")
    else:
        print("\nNo YARA matches found.")

    ext = analysis.get("extension", "")
    entropy = analysis.get("entropy", 0)

    blocked_exts = config["analysis_rules"]["blocked_extensions"]
    allowed_exts = config["analysis_rules"]["allowed_extensions"]

    try:
        if ext in blocked_exts:
            executor.move_to_requarantine(filepath)
        elif ext in allowed_exts:
            if entropy >= config["analysis_rules"]["entropy_thresholds"]["high"]:
                executor.move_to_requarantine(filepath)
            else:
                executor.move_to_safe(filepath)
        else:
            executor.move_to_requarantine(filepath)

        executor.generate_report(filepath, analysis)

    except Exception as e:
        logging.error(f"Error executing actions for {filepath}: {e}")
        print(f"[!] Error executing actions: {e}")
        
# --------- Performance Logger ----------
def performance_logger():
    logfile = "performance_log.csv"

    with open(logfile, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["time_seconds", "cpu_percent", "memory_percent"])

        t = 0
        while True:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory().percent

            writer.writerow([t, cpu, mem])
            f.flush()

            t += 1

# --------- Main ----------
if __name__ == "__main__":
    with open("config.json") as f:
        config = json.load(f)

    quarantine_folder = config["folders"]["quarantine"]
    file_queue = queue.Queue()
    executor = ActionExecutor(config)

    fancy_banner()

    # --------- Ask user if they want to start the GUI ----------
    launch_gui = input("Do you want to launch the PyScan GUI? (y/n): ").strip().lower()
    if launch_gui == 'y':
        # Launch GUI in a separate process to avoid Tkinter blocking CLI
        subprocess.Popen(["python", "pyscan_gui.py"])
        print("[*] GUI launched in parallel.")
        
    # --------- Start Performance Monitoring ----------
    perf_thread = threading.Thread(target=performance_logger, daemon=True)
    perf_thread.start()
    print("[*] Performance monitoring started.")

    # --------- Start watcher thread ----------
    watcher_thread = threading.Thread(target=start_watcher, args=(quarantine_folder, file_queue), daemon=True)
    watcher_thread.start()
    print(f"Monitoring quarantine folder: {quarantine_folder}\n")

    processed_files = set()

    try:
        while True:
            filepath = file_queue.get()
            if filepath in processed_files:
                continue
            process_file(filepath, executor, config)
            processed_files.add(filepath)
    except KeyboardInterrupt:
        print("\n[!] Stopping PyScan...")
        os._exit(0)
