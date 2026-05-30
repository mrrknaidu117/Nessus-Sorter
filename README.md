# Nessus CSV Sorter — Gemini AI Edition

An AI-powered vulnerability report aggregator and cleaner for Nessus CSV exports.

---

## Features

| Rule    | What it does |
|---------|-------------|
| **Case 1**  | Removes all rows where **Risk = None** (case-insensitive) |
| **Case 2**  | Merges duplicate rows for the same Plugin ID + Name + Host, keeping the **numerically latest CVE** and consolidating all unique port numbers |
| **Case 3**  | Fuzzy-groups vulnerabilities by software components and leverages **Google Gemini AI** to identify and replace older patch versions while merging port listings |

- Select and process **multiple input CSV files** simultaneously.
- Choose sorting mode: **Sort by Host IP** or **Sort by Vulnerability Name**.
- Modern Dark-Themed GUI built entirely in standard Python.
- Persistent API Key caching with automatic validation at startup.
- Zero-dependency architecture (runs natively without needing external pip packages).

---

## Installation & Setup

1. **Clone or download this repository:**
   ```bash
   git clone https://github.com/mrrknaidu117/Nessus-Sorter.git
   cd Nessus-Sorter
   ```

2. **Run the tool:**
   ```bash
   python nessus_sorter.py
   ```
   *(Note: No external packages are required! The tool runs on Python 3.8+ using native modules.)*

---

## Usage Guide

1. **Input File**: Click **Browse …** and select one or more Nessus `.csv` files.
2. **Sort Mode**: Select *Sort by IP* or *Sort by Name*.
3. **API Key (Optional)**:
   - Paste your free Google Gemini API Key.
   - Click **Validate key** to activate the Case 3 AI version cleaning.
   - *Once validated, the key is securely saved locally (`config.json`) and auto-loaded on next startup.*
4. Click **⚙ Process & Clean CSV**.
5. Once processing finishes, a save dialog will automatically prompt you to download the finalized, sorted CSV.

### Getting a Free Google Gemini API Key

1. Go to [Google AI Studio](https://aistudio.google.com/apikey).
2. Click **Create API Key**.
3. Copy the key (it starts with `AIza...`) and paste it into the application.

---

## Under the Hood

### CVE Deduplication (Case 2)
CVE IDs follow the standard `CVE-YYYY-NNNNN` format. The tool extracts the year and sequence number to mathematically identify and retain the newest CVE while safely merging unique ports across the group:
- `CVE-2015-1682` (removed, but port merged)
- `CVE-2015-1683` (retained as latest CVE)

### Version Deduplication (Case 3)
The tool strips version numbers to group similar vulnerability names, then queries Google Gemini (`gemini-flash-latest`) via zero-dependency HTTP post requests:
> *"Identify the ONE string that represents the MOST RECENT (latest) version. Reply ONLY with the exact string from the list."*

The tool automatically replaces the older version entries with the latest version name and consolidates the port listings under a single row per host.
*(If no API Key is provided, the tool falls back to comparing the Plugin Modification Date).*

---

## License

This project is licensed under the MIT License. Feel free to use and customize it!
