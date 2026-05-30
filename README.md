# PyScan
PyScan is a lightweight Python-based malware analysis tool that performs real-time monitoring and static analysis of files in quarantine folders. It uses entropy analysis, metadata extraction, hash generation, suspicious string detection, and YARA rule matching to identify potentially malicious files through both CLI and GUI interfaces.

# Installation and Usage

## 1. Clone the Repository

```bash
git clone https://github.com/yourusername/pyscan.git
cd pyscan
```

---

## 2. Create a Virtual Environment

```bash
python3 -m venv venv
```

---

## 3. Activate the Virtual Environment

### Linux / Kali

```bash
source venv/bin/activate
```

### Windows

```bash
venv\Scripts\activate
```

---

## 4. Install Required Dependencies

```bash
pip install -r requirements.txt
```

---

## 5. Run PyScan

### CLI Mode

```bash
python pyscan_cli.py
```

### GUI Mode

```bash
python pyscan_gui.py
```

---

## 6. Add Files for Analysis

Place suspicious or sample files inside the `quarantine/` folder.
PyScan will automatically detect, analyze, classify, and process them in real time.

---

## 7. View Results

* Logs are stored in:

```bash
analysis_actions.log
```

* JSON reports are generated inside:

```bash
reports/
```

* Processed files are moved to:

```bash
safe/
re-quarantine/
```
