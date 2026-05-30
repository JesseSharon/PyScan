# analyzer.py
# Rewritten analyzer with integrated YARA scanning.
# Produces both detailed `yara_matches` and simplified `yara` (as Option B) in the analysis result.
# YARA engine is optional — code runs even if yara-python is not installed.

import os
import hashlib
import math
import re
import mimetypes
import time
from datetime import datetime

# YARA import (optional)
try:
    import yara
except Exception:
    yara = None

# -------------------------
# Helper functions
# -------------------------
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    # count bytes once to avoid repeated .count calls
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    for count in freq:
        if count == 0:
            continue
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def byte_frequency_stats(data: bytes):
    """Return (min, max, avg) frequency of byte values (fractions)."""
    if not data:
        return (0.0, 0.0, 0.0)
    length = len(data)
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    freqs = [f / length for f in freq]
    return (min(freqs), max(freqs), sum(freqs) / 256.0)

def has_suspicious_strings(data: bytes):
    try:
        text = data.decode(errors='ignore').lower()
    except Exception:
        return (False, [])
    suspicious_patterns = [
        r'cmd\.exe',
        r'powershell',
        r'base64',
        r'eval\(',
        r'system\(',
        r'exec\(',
        r'http[s]?://',
        r'//',           # simple indicator (could be noisy)
        r'<script',
        r'\.dll\b',
    ]
    matched = []
    for pattern in suspicious_patterns:
        if re.search(pattern, text):
            matched.append(pattern)
    return (len(matched) > 0, matched)

# -------------------------
# YARA loader & scanner
# -------------------------
def load_yara_engine():
    """
    Compile YARA rules from 'rules/' or 'yara_rules/' if yara-python is installed.
    Returns compiled engine or None if not available.
    """
    if yara is None:
        # yara-python not installed
        return None

    rule_dirs = ["rules", "yara_rules"]
    rule_files = []
    for d in rule_dirs:
        if os.path.isdir(d):
            for fname in sorted(os.listdir(d)):
                if fname.lower().endswith((".yar", ".yara")):
                    rule_files.append(os.path.join(d, fname))

    if not rule_files:
        return None

    try:
        filepaths = {str(i): rule_files[i] for i in range(len(rule_files))}
        engine = yara.compile(filepaths=filepaths)
        return engine
    except Exception:
        # compilation error -> disable YARA to avoid crashing analyzer
        return None

# compile once
YARA_ENGINE = load_yara_engine()

def _get_severity_from_meta(meta: dict):
    """
    Determine severity string from YARA rule meta.
    Accept common keys: severity, level, risk.
    Falls back to 'UNKNOWN'.
    """
    if not isinstance(meta, dict):
        return "UNKNOWN"
    for key in ("severity", "level", "risk", "score"):
        if key in meta:
            val = str(meta[key]).strip()
            if val:
                return val.upper()
    # infer from tags if present
    tags = meta.get("tags") if "tags" in meta else None
    if tags:
        if isinstance(tags, (list, tuple)):
            tags_lower = [t.lower() for t in tags]
            if "high" in tags_lower or "critical" in tags_lower:
                return "HIGH"
            if "medium" in tags_lower:
                return "MEDIUM"
            if "low" in tags_lower:
                return "LOW"
    return "UNKNOWN"

def _extract_match_summary(match_obj):
    """
    Convert a yara.match object to a dict summary.
    Keeps rule_name, severity, meta, tags, small matched_strings list and timestamp.
    """
    try:
        rule_name = getattr(match_obj, "rule", None) or match_obj.rule
    except Exception:
        rule_name = "unknown"

    tags = list(getattr(match_obj, "tags", [])) if hasattr(match_obj, "tags") else []
    meta = dict(getattr(match_obj, "meta", {})) if hasattr(match_obj, "meta") else {}

    # matched string identifiers (up to first 10) - avoid dumping raw bytes
    matched_string_ids = []
    try:
        for t in getattr(match_obj, "strings", [])[:10]:
            # tuple structure: (offset, identifier, matched_bytes)
            if len(t) >= 2:
                matched_string_ids.append(t[1])
    except Exception:
        matched_string_ids = []

    severity = _get_severity_from_meta(meta)
    timestamp = datetime.utcnow().isoformat() + "Z"

    return {
        "rule_name": rule_name,
        "severity": severity,
        "meta": meta,
        "tags": tags,
        "matched_strings": matched_string_ids,
        "timestamp": timestamp,
    }

# -------------------------
# Main analyze_file()
# -------------------------
def analyze_file(filepath: str) -> dict:
    """
    Perform static analysis on filepath and return a dictionary with:
    - file metadata (names, sizes, times)
    - hashes (sha256, md5, sha1)
    - entropy and byte stats
    - suspicious string indicators
    - yara_matches (detailed) and yara (simplified list of dicts)
    - risk_level and risk_rationale
    """
    result = {}
    try:
        # Basic file metadata
        result["file_name"] = os.path.basename(filepath)
        result["file_path"] = filepath
        result["file_size_bytes"] = os.path.getsize(filepath)
        result["last_modified"] = time.ctime(os.path.getmtime(filepath))
        result["created_time"] = time.ctime(os.path.getctime(filepath))
        result["accessed_time"] = time.ctime(os.path.getatime(filepath))

        with open(filepath, "rb") as f:
            data = f.read()

        # Entropy & byte stats
        entropy = calculate_entropy(data)
        min_freq, max_freq, avg_freq = byte_frequency_stats(data)

        # Hashes
        result["sha256"] = hashlib.sha256(data).hexdigest()
        result["md5"] = hashlib.md5(data).hexdigest()
        result["sha1"] = hashlib.sha1(data).hexdigest()

        result["entropy"] = entropy
        result["byte_freq_min"] = min_freq
        result["byte_freq_max"] = max_freq
        result["byte_freq_avg"] = avg_freq

        # Extension and mimetype
        _, ext = os.path.splitext(filepath)
        ext = ext.lower()
        result["extension"] = ext
        mime_type = mimetypes.guess_type(filepath)[0]
        result["mime_type"] = mime_type if mime_type else "unknown"

        # Suspicious string detection
        suspicious_found, matched_patterns = has_suspicious_strings(data)
        result["suspicious_strings_found"] = suspicious_found
        result["suspicious_patterns_matched"] = matched_patterns

        # ---------------------------
        # YARA scanning (two outputs)
        # - result["yara_matches"] : detailed summaries (full objects)
        # - result["yara"] : simplified list of dicts matching Option B (rule_name,severity,timestamp)
        # ---------------------------
        detailed_matches = []
        simplified_matches = []
        result["yara_matches"] = detailed_matches  # detailed
        result["yara"] = simplified_matches        # simplified (Option B)

        if YARA_ENGINE:
            try:
                matches = YARA_ENGINE.match(filepath)
                for m in matches:
                    md = _extract_match_summary(m)
                    detailed_matches.append(md)
                    simplified_matches.append({
                        "rule_name": md.get("rule_name"),
                        "severity": md.get("severity"),
                        "timestamp": md.get("timestamp")
                    })
            except Exception as ye:
                # keep error visible in detailed matches
                detailed_matches.append({"error": f"YARA error: {ye}"})
        else:
            # YARA not available -> leave lists empty
            pass

        # ---------------------------
        # Risk classification parameters & logic
        # ---------------------------
        blocked_exts = {".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".vbs", ".js", ".jar", ".msi", ".apk", ".dll"}
        allowed_exts = {".txt", ".log", ".json", ".xml", ".csv", ".pdf", ".doc", ".docx", ".jpg", ".jpeg", ".png", ".gif", ".webp"}

        # Digital-signature placeholder (simple heuristic)
        is_signed = False if ext in blocked_exts else True
        result["is_signed"] = is_signed

        rationale = []
        risk_level = "Medium"

        # Priority: YARA hits (real rule matches) bump to High
        if simplified_matches:
            # ensure these are real matches (not just error entries)
            has_real = any(m.get("rule_name") for m in simplified_matches)
            if has_real:
                risk_level = "High"
                rationale.append("YARA rule matched: possible malware")

        # if no YARA match determined risk by other heuristics
        if risk_level != "High":
            if ext in blocked_exts:
                risk_level = "High"
                rationale.append("File has blocked extension")
            elif entropy >= 8.5 and result["file_size_bytes"] > 10 * 1024:
                risk_level = "High"
                rationale.append(f"High entropy {entropy:.2f} with large size")
            elif entropy >= 8.0 or suspicious_found:
                risk_level = "Medium"
                rationale.append(f"Moderate entropy {entropy:.2f} or suspicious strings found")
            elif ext in allowed_exts and entropy < 7.5:
                risk_level = "Low"
                rationale.append("Allowed extension with low entropy")
            else:
                risk_level = "Medium"
                rationale.append("Default medium risk")

        # unsigned executable-like files are at least Medium
        if not is_signed and risk_level != "High":
            risk_level = "Medium"
            rationale.append("Unsigned executable-like file")

        result["risk_level"] = risk_level
        result["risk_rationale"] = rationale

    except Exception as e:
        result["error"] = str(e)

    return result
