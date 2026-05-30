import os
import shutil
import json
import logging

class ActionExecutor:
    def __init__(self, config):
        self.quarantine_dir = config["folders"]["quarantine"]
        self.re_quarantine_dir = config["folders"]["re_quarantine"]
        self.safe_dir = config["folders"]["safe"]
        self.reports_dir = config["folders"]["reports"]
        self.entropy_high = config["analysis_rules"]["entropy_thresholds"]["high"]
        self.entropy_medium = config["analysis_rules"]["entropy_thresholds"]["medium"]
        self.blocked_exts = set(config["analysis_rules"]["blocked_extensions"])
        self.allowed_exts = set(config["analysis_rules"]["allowed_extensions"])

        # Create folders if missing
        for d in [self.quarantine_dir, self.re_quarantine_dir, self.safe_dir, self.reports_dir]:
            os.makedirs(d, exist_ok=True)

    def generate_report(self, file_path, analysis_result):
        report_name = os.path.basename(file_path) + "_report.json"
        report_path = os.path.join(self.reports_dir, report_name)
        with open(report_path, "w") as f:
            json.dump(analysis_result, f, indent=4)
        logging.info(f"Report created: {report_path}")

    def move_file(self, src, dest_dir):
        dest = os.path.join(dest_dir, os.path.basename(src))
        shutil.move(src, dest)
        logging.info(f"Moved '{src}' to '{dest}'")

    # Convenience methods
    def move_to_requarantine(self, file_path):
        self.move_file(file_path, self.re_quarantine_dir)

    def move_to_safe(self, file_path):
        self.move_file(file_path, self.safe_dir)

    def move_to_quarantine(self, file_path):
        self.move_file(file_path, self.quarantine_dir)

    def decide_action(self, file_path, analysis_result):
        ext = os.path.splitext(file_path)[1].lower()
        entropy = analysis_result.get("entropy", 0)

        # Blocked extension -> move to re-quarantine
        if ext in self.blocked_exts:
            logging.info(f"Blocked extension detected: {ext}")
            self.move_to_requarantine(file_path)
            return "re_quarantine"

        # High entropy -> move to re-quarantine
        if entropy >= self.entropy_high:
            logging.info(f"High entropy ({entropy:.2f}) detected")
            self.move_to_requarantine(file_path)
            return "re_quarantine"
        
        if ext in self.allowed_exts:
            logging.info(f"Allowed extension {ext} considered safe regardless of entropy")
            self.move_to_safe(file_path)
            return "safe"

        # Medium entropy -> move to re-quarantine
        if self.entropy_medium <= entropy < self.entropy_high:
            logging.info(f"Medium entropy ({entropy:.2f}) detected")
            self.move_to_requarantine(file_path)
            return "re_quarantine"

        # Allowed extension and low entropy -> move to safe
        if ext in self.allowed_exts and entropy < self.entropy_medium:
            self.move_to_safe(file_path)
            return "safe"

        # Default: keep in quarantine
        logging.info("Default action: keep in quarantine")
        return "quarantine"
