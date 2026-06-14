import csv
import json
import os
import re
from datetime import datetime
import urllib.request
import urllib.error

# ══════════════════════════════════════════════════════════════════════════════
#  GEMINI FREE API  (built-in urllib — no pip install needed)
# ══════════════════════════════════════════════════════════════════════════════

GEMINI_MODEL = "gemini-flash-latest"
GEMINI_URL   = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    + GEMINI_MODEL
    + ":generateContent?key={api_key}"
)


def call_gemini(prompt: str, api_key: str) -> str:
    """POST prompt to Gemini REST API. Returns text response or raises RuntimeError."""
    url     = GEMINI_URL.format(api_key=api_key)
    payload = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0, "maxOutputTokens": 300}
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Gemini HTTP {e.code}: {body[:300]}")
    except Exception as e:
        raise RuntimeError(str(e))


def validate_gemini_key(api_key: str):
    """Return (True, '') if key works, else (False, error_message)."""
    try:
        result = call_gemini("Reply with exactly one word: OK", api_key)
        return (True, "") if result else (False, "Empty response from Gemini.")
    except RuntimeError as e:
        return False, str(e)


# ══════════════════════════════════════════════════════════════════════════════
#  CORE PARSING AND CLEANING RULES
# ══════════════════════════════════════════════════════════════════════════════

def parse_nessus_csv(filepath: str):
    """Read Nessus CSV and return (headers list, list of row dicts)."""
    rows = []
    with open(filepath, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        headers = list(reader.fieldnames or [])
        for row in reader:
            rows.append(dict(row))
    return headers, rows


def cve_sort_key(cve: str):
    """Return (year, seq) numeric tuple. Higher = newer CVE."""
    if not cve or not cve.upper().startswith("CVE-"):
        return (-1, -1)
    parts = cve.upper().replace("CVE-", "").split("-")
    try:
        return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
    except ValueError:
        return (-1, -1)


# ── Case 1 ────────────────────────────────────────────────────────────────────

def case1_remove_none_risk(rows: list, log) -> list:
    """Remove every row whose Risk column equals 'None' (case-insensitive)."""
    before = len(rows)
    kept   = [r for r in rows if (r.get("Risk") or "").strip().lower() != "none"]
    log(f"Case 1 › Removed {before - len(kept)} rows with Risk = None  |  Remaining: {len(kept)}", "ok")
    return kept


# ── Case 2 ────────────────────────────────────────────────────────────────────

def case2_dedup_same_plugin_latest_cve(rows: list, log) -> list:
    """
    Same Plugin ID + Name + Host with multiple CVEs →
    keep only the row with the numerically latest CVE.
    """
    groups: dict = {}
    for r in rows:
        key = (r.get("Plugin ID", ""), r.get("Name", ""), r.get("Host", ""))
        groups.setdefault(key, []).append(r)

    result, removed = [], 0
    for group in groups.values():
        if len(group) == 1:
            result.append(group[0])
        else:
            best = sorted(group,
                          key=lambda r: cve_sort_key(r.get("CVE", "")),
                          reverse=True)[0]
            
            # Merge ports
            ports = []
            for r in group:
                port_str = str(r.get("Port", "")).strip()
                if port_str:
                    ports.extend([p.strip() for p in port_str.split(",") if p.strip()])
            if ports:
                best["Port"] = ", ".join(list(dict.fromkeys(ports)))

            result.append(best)
            removed += len(group) - 1

    log(f"Case 2 › Removed {removed} older-CVE duplicates (ports merged)  |  Remaining: {len(result)}", "ok")
    return result


# ── Case 3 ────────────────────────────────────────────────────────────────────

def _strip_version(name: str) -> str:
    """Normalise name: remove version numbers and parenthesised suffixes."""
    s = re.sub(r"\([^)]*\)", "", name)
    s = re.sub(r"[\d.]+",    "", s)
    return re.sub(r"\s+", " ", s).strip().lower()[:60]


def _mod_date(row: dict) -> datetime:
    """Parse Plugin Modification Date (or Publication Date) to datetime."""
    raw = (row.get("Plugin Modification Date") or
           row.get("Plugin Publication Date") or "").strip()
    for fmt in ("%Y/%m/%d", "%d-%m-%Y", "%Y-%m-%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return datetime.min


def case3_dedup_same_component_different_version(
    rows: list, log,
    api_key: str = "",
    use_ai:  bool = True
) -> list:
    """
    Fuzzy-group rows by component name (version stripped).
    Ask Gemini AI which entries are older patch versions → replace them with latest.
    Merge ports for duplicate vulnerabilities on the same Host.
    """
    # 1. Get unique names and map to base names
    unique_names = list(set(r.get("Name", "") for r in rows if r.get("Name")))
    groups: dict = {}
    for name in unique_names:
        base = _strip_version(name)
        groups.setdefault(base, []).append(name)

    multi = {k: v for k, v in groups.items() if len(v) > 1}
    log(f"Case 3 › {len(multi)} potential version-groups found …", "info")

    name_to_date = {}
    for r in rows:
        n = r.get("Name", "")
        d = _mod_date(r)
        if n not in name_to_date or d > name_to_date[n]:
            name_to_date[n] = d

    name_mapping = {}

    for base_name, name_list in multi.items():
        fallback_latest = sorted(name_list, key=lambda n: name_to_date.get(n, datetime.min))[-1]
        if use_ai and api_key:
            items_text = "\n".join(name_list)
            prompt = (
                "You are a cybersecurity expert.\n"
                "The following list contains vulnerability names which represent different patch versions of the same component.\n\n"
                f"{items_text}\n\n"
                "Identify the ONE string that represents the MOST RECENT (latest) version.\n"
                "Reply ONLY with the exact string from the list. No quotes, no markdown, no other text."
            )
            try:
                raw = call_gemini(prompt, api_key)
                raw = re.sub(r"```[a-z]*", "", raw).strip().strip("`").strip().strip('"').strip("'")
                
                latest_name = fallback_latest
                for n in name_list:
                    if n.lower() == raw.lower() or raw in n:
                        latest_name = n
                        break
            except Exception as exc:
                log(f"  Gemini error ({base_name[:30]}…): {exc} — fallback used", "warn")
                latest_name = fallback_latest
        else:
            latest_name = fallback_latest

        for n in name_list:
            if n != latest_name:
                name_mapping[n] = latest_name

    # Apply mapping to rows
    for r in rows:
        old_name = r.get("Name", "")
        if old_name in name_mapping:
            r["Name"] = name_mapping[old_name]

    # 2. Group by Host + Name to merge duplicates created by mapping
    final_groups: dict = {}
    for r in rows:
        key = (r.get("Host", ""), r.get("Name", ""))
        final_groups.setdefault(key, []).append(r)

    result = []
    removed = 0
    for group in final_groups.values():
        if len(group) == 1:
            result.append(group[0])
        else:
            # Sort by CVE to find best row
            best = sorted(group, key=lambda r: cve_sort_key(r.get("CVE", "")), reverse=True)[0]
            
            # Merge ports
            ports = []
            for r in group:
                port_str = str(r.get("Port", "")).strip()
                if port_str:
                    ports.extend([p.strip() for p in port_str.split(",") if p.strip()])
            if ports:
                best["Port"] = ", ".join(list(dict.fromkeys(ports)))
                
            result.append(best)
            removed += len(group) - 1

    log(f"Case 3 › Mapped older versions & removed {removed} duplicates (ports merged) |  Remaining: {len(result)}", "ok")
    return result


# ── Sorting & Writing Helpers ──────────────────────────────────────────────────

def sort_rows_by_ip(rows: list) -> list:
    """Sort rows by Host IP address numerically."""
    def ip_key(r):
        try:
            return tuple(int(p) for p in (r.get("Host") or "").split("."))
        except ValueError:
            return (0, 0, 0, 0)
    return sorted(rows, key=ip_key)


def write_csv(headers: list, rows: list, filepath: str):
    """Write list of row dicts into a CSV file."""
    with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ══════════════════════════════════════════════════════════════════════════════
#  PIPELINE ENTRY POINTS
# ══════════════════════════════════════════════════════════════════════════════

def run_cleanup_pipeline(paths: list, api_key: str, use_ai: bool, log) -> tuple:
    """Read all CSV paths, run cleaning rules (Case 1, 2, and 3), return (first_headers, cleaned_rows)."""
    all_headers = []
    all_rows = []
    for path in paths:
        log(f"Reading: {os.path.basename(path)}", "info")
        headers, rows = parse_nessus_csv(path)
        if not all_headers:
            all_headers = headers
        all_rows.extend(rows)

    log(f"Loaded a total of {len(all_rows)} rows.", "info")
    total_before = len(all_rows)

    # Case 1: Remove risk = none
    rows = case1_remove_none_risk(all_rows, log)
    none_removed = total_before - len(rows)

    # Case 2: Same plugin ID + name + host -> keep latest CVE
    rows = case2_dedup_same_plugin_latest_cve(rows, log)

    # Case 3: Version deduplication
    rows = case3_dedup_same_component_different_version(
        rows, log, api_key=api_key, use_ai=use_ai
    )
    deduped = (total_before - none_removed) - len(rows)

    return all_headers, rows, total_before, none_removed, deduped


def run_ip_sorting_pipeline(paths: list, api_key: str, use_ai: bool, log) -> tuple:
    """Run full cleanup, sort by IP, and return (headers, sorted_rows, total, none_removed, deduped)."""
    headers, rows, total, none_removed, deduped = run_cleanup_pipeline(paths, api_key, use_ai, log)
    sorted_rows = sort_rows_by_ip(rows)
    log("Sorted by IP address.", "ok")
    return headers, sorted_rows, total, none_removed, deduped
