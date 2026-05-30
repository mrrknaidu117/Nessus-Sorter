"""
Nessus CSV Sorter  —  Google Gemini AI Edition
================================================
Uses Google Gemini FREE API for Case 3 AI deduplication.
No extra packages needed — uses Python built-in urllib only.

Get your free Gemini API key (no credit card needed):
    1. Go to: https://aistudio.google.com/apikey
    2. Click the copy icon next to your key  (starts with AIza...)
    3. Paste it into the tool's API Key field at runtime

NEVER hardcode your API key in this file.

Run:
    python nessus_sorter.py
"""

import csv
import json
import os
import re
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
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
#  CORE PROCESSING LOGIC
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


# ── Sort & write ──────────────────────────────────────────────────────────────

def sort_rows(rows: list, mode: str) -> list:
    if mode == "ip":
        def ip_key(r):
            try:
                return tuple(int(p) for p in (r.get("Host") or "").split("."))
            except ValueError:
                return (0, 0, 0, 0)
        return sorted(rows, key=ip_key)
    return sorted(rows, key=lambda r: (r.get("Name") or "").lower())


def write_csv(headers: list, rows: list, filepath: str):
    with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ══════════════════════════════════════════════════════════════════════════════
#  COLOUR PALETTE
# ══════════════════════════════════════════════════════════════════════════════

BG          = "#0f1117"
SURFACE     = "#1a1d27"
SURFACE2    = "#22263a"
ACCENT      = "#4f8ef7"
GEMINI_BLUE = "#1a73e8"
SUCCESS     = "#22c55e"
WARNING     = "#f59e0b"
DANGER      = "#ef4444"
TEXT        = "#e8eaf0"
TEXT_MUTED  = "#6b7280"
BORDER      = "#2d3148"
MONO        = "Consolas" if os.name == "nt" else "Menlo"


# ══════════════════════════════════════════════════════════════════════════════
#  GUI APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

PLACEHOLDER_KEY  = "Paste your Gemini API key here  (AIza…)"
PLACEHOLDER_FILE = "Select your Nessus-exported .csv file …"


class NessusSorterApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Nessus CSV Sorter  —  Gemini AI Edition")
        self.geometry("860x760")
        self.minsize(720, 620)
        self.configure(bg=BG)
        self.resizable(True, True)

        self.sort_mode   = tk.StringVar(value="ip")
        self.use_ai_var  = tk.BooleanVar(value=True)
        self.result_rows = []
        self.result_hdrs = []
        self.processing  = False
        self._key_valid  = False
        self._input_paths = []
        self._api_key    = ""

        self._build_ui()
        self._apply_scrollbar_style()
        self._load_config()

    def _load_config(self):
        config_path = os.path.join(os.path.dirname(__file__), "config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    saved_key = config.get("api_key", "")
                    if saved_key:
                        self.key_entry.delete(0, "end")
                        self.key_entry.config(fg=TEXT, show="*")
                        self.key_entry.insert(0, saved_key)
                        self._validate_key_thread()
            except Exception:
                pass

    def _save_config(self, key):
        config_path = os.path.join(os.path.dirname(__file__), "config.json")
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump({"api_key": key}, f)
        except Exception:
            pass

    # ── UI BUILD ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        pad = tk.Frame(self, bg=BG)
        pad.pack(fill="both", expand=True, padx=26, pady=20)

        # Header
        hdr = tk.Frame(pad, bg=BG)
        hdr.pack(fill="x", pady=(0, 4))
        tk.Label(hdr, text="Nessus CSV Sorter",
                 font=("Segoe UI", 22, "bold"), bg=BG, fg=TEXT).pack(side="left")
        tk.Label(hdr, text="  ✦ Gemini AI  ",
                 font=("Segoe UI", 10, "bold"),
                 bg=GEMINI_BLUE, fg="white", padx=8, pady=3).pack(side="left", padx=(10, 0))
        tk.Label(pad,
                 text="Clean Nessus CSV exports: remove None-risk rows, deduplicate CVEs, "
                      "and drop older patch versions — powered by Google Gemini AI (free).",
                 font=("Segoe UI", 10), bg=BG, fg=TEXT_MUTED,
                 wraplength=800, justify="left").pack(anchor="w", pady=(4, 18))

        # 1. Input file
        self._section_label(pad, "1  INPUT FILE")
        fr = tk.Frame(pad, bg=BG)
        fr.pack(fill="x", pady=(4, 0))
        self.path_entry = tk.Entry(
            fr, font=("Segoe UI", 10), bg=SURFACE2, fg=TEXT_MUTED,
            insertbackground=TEXT, relief="flat", bd=0,
            highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT
        )
        self.path_entry.insert(0, PLACEHOLDER_FILE)
        self.path_entry.bind("<FocusIn>",  self._file_focus_in)
        self.path_entry.bind("<FocusOut>", self._file_focus_out)
        self.path_entry.pack(side="left", fill="x", expand=True, ipady=7)
        self._make_btn(fr, "Browse …", self._browse_input, ACCENT).pack(side="left", padx=(8, 0))

        # 2. Sort mode
        self._section_label(pad, "2  SORT MODE")
        sr = tk.Frame(pad, bg=BG)
        sr.pack(fill="x", pady=(4, 0))
        for val, icon, lbl, desc in [
            ("ip",   "🌐", "Sort by IP",   "Group vulnerabilities by host IP address"),
            ("name", "🏷", "Sort by Name", "Group vulnerabilities by plugin name"),
        ]:
            self._radio_card(sr, val, icon, lbl, desc).pack(side="left", padx=(0, 10))

        # 3. Processing rules
        self._section_label(pad, "3  PROCESSING RULES  (always applied)")
        cr = tk.Frame(pad, bg=BG)
        cr.pack(fill="x", pady=(4, 0))
        for title, desc in [
            ("Case 1 — Remove None",      "Drop all rows where Risk = 'None'"),
            ("Case 2 — Deduplicate CVEs", "Same plugin + host → keep latest CVE"),
            ("Case 3 — Version dedup",    "Same component → AI keeps newest patch"),
        ]:
            self._info_chip(cr, title, desc).pack(side="left", padx=(0, 8), fill="y")

        # 4. Gemini API key
        self._section_label(pad, "4  GOOGLE GEMINI API KEY  (free — no credit card needed)")
        info_box = tk.Frame(pad, bg=SURFACE2, padx=14, pady=10)
        info_box.pack(fill="x", pady=(4, 10))
        tk.Label(info_box,
                 text="How to get your key:\n"
                      "  1. Go to  https://aistudio.google.com/apikey\n"
                      "  2. Click the copy icon next to your existing key\n"
                      "  3. Paste it below — Free tier: 1500 requests/day, no credit card",
                 font=("Segoe UI", 9), bg=SURFACE2, fg=TEXT_MUTED,
                 justify="left").pack(anchor="w")

        key_row = tk.Frame(pad, bg=BG)
        key_row.pack(fill="x")
        self.key_entry = tk.Entry(
            key_row, font=("Segoe UI", 10), bg=SURFACE2, fg=TEXT_MUTED,
            insertbackground=TEXT, relief="flat", bd=0,
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=GEMINI_BLUE, show=""
        )
        self.key_entry.insert(0, PLACEHOLDER_KEY)
        self.key_entry.bind("<FocusIn>",  self._key_focus_in)
        self.key_entry.bind("<FocusOut>", self._key_focus_out)
        self.key_entry.pack(side="left", fill="x", expand=True, ipady=7)

        self.validate_btn = self._make_btn(
            key_row, "  Validate key  ", self._validate_key_thread, GEMINI_BLUE)
        self.validate_btn.pack(side="left", padx=(8, 0))

        self.key_status_lbl = tk.Label(pad, text="", font=("Segoe UI", 9), bg=BG, fg=TEXT_MUTED)
        self.key_status_lbl.pack(anchor="w", pady=(5, 0))

        chk_row = tk.Frame(pad, bg=BG)
        chk_row.pack(anchor="w", pady=(6, 0))
        tk.Checkbutton(chk_row, text="Use Gemini AI for Case 3",
                       variable=self.use_ai_var,
                       font=("Segoe UI", 10), bg=BG, fg=TEXT,
                       activebackground=BG, selectcolor=SURFACE2).pack(side="left")
        tk.Label(chk_row,
                 text="   (uncheck → uses Plugin Modification Date instead)",
                 font=("Segoe UI", 9), bg=BG, fg=TEXT_MUTED).pack(side="left")

        # Process button
        self.process_btn = self._make_btn(
            pad, "⚙   Process & Clean CSV",
            self._start_processing, ACCENT,
            font=("Segoe UI", 12, "bold"), pady=11
        )
        self.process_btn.pack(fill="x", pady=(18, 0))

        # Log
        self._section_label(pad, "LOG")
        log_frame = tk.Frame(pad, bg=SURFACE, highlightthickness=1,
                             highlightbackground=BORDER)
        log_frame.pack(fill="both", expand=True, pady=(4, 0))
        self.log_text = tk.Text(
            log_frame, bg=SURFACE, fg=TEXT_MUTED,
            font=(MONO, 10), bd=0, padx=10, pady=8,
            state="disabled", wrap="word", height=8
        )
        sb = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log_text.pack(fill="both", expand=True)
        self.log_text.tag_config("ok",   foreground=SUCCESS)
        self.log_text.tag_config("warn", foreground=WARNING)
        self.log_text.tag_config("err",  foreground=DANGER)
        self.log_text.tag_config("info", foreground=TEXT_MUTED)

        # Stats + Export
        bot = tk.Frame(pad, bg=BG)
        bot.pack(fill="x", pady=(14, 0))
        self.stats_frame = tk.Frame(bot, bg=BG)
        self.stats_frame.pack(side="left", fill="x", expand=True)
        self.export_btn = self._make_btn(
            bot, "⬇   Export Cleaned CSV",
            self._export_csv, SUCCESS,
            font=("Segoe UI", 11, "bold"), pady=10
        )
        self.export_btn.pack(side="right")
        self.export_btn.config(state="disabled")

    # ── WIDGET HELPERS ────────────────────────────────────────────────────────

    def _section_label(self, parent, text):
        tk.Label(parent, text=text, font=("Segoe UI", 8, "bold"),
                 bg=BG, fg=TEXT_MUTED).pack(anchor="w", pady=(14, 2))

    def _make_btn(self, parent, text, cmd, color,
                  font=("Segoe UI", 10), pady=6):
        b = tk.Button(
            parent, text=text, command=cmd,
            font=font, bg=color, fg="white",
            activebackground=self._darken(color), activeforeground="white",
            relief="flat", bd=0, cursor="hand2", pady=pady, padx=14
        )
        b.bind("<Enter>", lambda _: b.config(bg=self._darken(color)))
        b.bind("<Leave>", lambda _: b.config(bg=color))
        return b

    def _radio_card(self, parent, value, icon, label, desc):
        f = tk.Frame(parent, bg=SURFACE2, highlightthickness=1,
                     highlightbackground=BORDER, cursor="hand2", padx=14, pady=10)
        rb = tk.Radiobutton(
            f, text=f"{icon}  {label}", variable=self.sort_mode, value=value,
            font=("Segoe UI", 10, "bold"), bg=SURFACE2, fg=TEXT,
            activebackground=SURFACE2, selectcolor=SURFACE2
        )
        rb.pack(anchor="w")
        tk.Label(f, text=desc, font=("Segoe UI", 9),
                 bg=SURFACE2, fg=TEXT_MUTED).pack(anchor="w")

        def _refresh(*_):
            f.config(highlightbackground=ACCENT if self.sort_mode.get() == value else BORDER)
        self.sort_mode.trace_add("write", _refresh)
        f.bind("<Button-1>", lambda _: self.sort_mode.set(value))
        _refresh()
        return f

    def _info_chip(self, parent, title, desc):
        f = tk.Frame(parent, bg=SURFACE2, highlightthickness=1,
                     highlightbackground=BORDER, padx=10, pady=8)
        tk.Label(f, text=title, font=("Segoe UI", 9, "bold"),
                 bg=SURFACE2, fg=TEXT).pack(anchor="w")
        tk.Label(f, text=desc, font=("Segoe UI", 8), bg=SURFACE2,
                 fg=TEXT_MUTED, wraplength=165, justify="left").pack(anchor="w", pady=(2, 0))
        return f

    def _stat_card(self, parent, value, label, color=TEXT):
        f = tk.Frame(parent, bg=SURFACE2, padx=16, pady=10)
        tk.Label(f, text=str(value), font=("Segoe UI", 20, "bold"),
                 bg=SURFACE2, fg=color).pack()
        tk.Label(f, text=label, font=("Segoe UI", 9),
                 bg=SURFACE2, fg=TEXT_MUTED).pack()
        return f

    @staticmethod
    def _darken(hex_color: str) -> str:
        r, g, b = int(hex_color[1:3], 16), int(hex_color[3:5], 16), int(hex_color[5:7], 16)
        f = 0.80
        return "#{:02x}{:02x}{:02x}".format(int(r*f), int(g*f), int(b*f))

    def _apply_scrollbar_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("Vertical.TScrollbar",
                    background=SURFACE2, troughcolor=SURFACE,
                    bordercolor=SURFACE, arrowcolor=TEXT_MUTED, relief="flat")

    # ── PLACEHOLDER HANDLERS ──────────────────────────────────────────────────

    def _file_focus_in(self, _):
        if self.path_entry.get() == PLACEHOLDER_FILE and \
                self.path_entry.cget("fg") == TEXT_MUTED:
            self.path_entry.delete(0, "end")
            self.path_entry.config(fg=TEXT)

    def _file_focus_out(self, _):
        if not self.path_entry.get():
            self.path_entry.insert(0, PLACEHOLDER_FILE)
            self.path_entry.config(fg=TEXT_MUTED)

    def _key_focus_in(self, _):
        if self.key_entry.get() == PLACEHOLDER_KEY and \
                self.key_entry.cget("fg") == TEXT_MUTED:
            self.key_entry.delete(0, "end")
            self.key_entry.config(fg=TEXT, show="*")

    def _key_focus_out(self, _):
        if not self.key_entry.get():
            self.key_entry.config(show="")
            self.key_entry.insert(0, PLACEHOLDER_KEY)
            self.key_entry.config(fg=TEXT_MUTED)

    # ── VALIDATE API KEY ──────────────────────────────────────────────────────

    def _validate_key_thread(self):
        key = self.key_entry.get().strip()
        if not key or key == PLACEHOLDER_KEY:
            self.key_status_lbl.config(
                text="⚠  Please paste your Gemini API key first.", fg=WARNING)
            return
        self._api_key = key
        self.validate_btn.config(state="disabled", text="  Checking …  ")
        self.key_status_lbl.config(text="Contacting Gemini …", fg=TEXT_MUTED)
        threading.Thread(target=self._do_validate, args=(key,), daemon=True).start()

    def _do_validate(self, key: str):
        ok, err = validate_gemini_key(key)
        self._key_valid = ok
        if ok:
            self._save_config(key)
            self.after(0, lambda: self.key_status_lbl.config(
                text="✓  Key is valid — Gemini AI ready!", fg=SUCCESS))
        else:
            self.after(0, lambda: self.key_status_lbl.config(
                text=f"✗  {err[:130]}", fg=DANGER))
        self.after(0, lambda: self.validate_btn.config(
            state="normal", text="  Validate key  "))

    # ── BROWSE ────────────────────────────────────────────────────────────────

    def _browse_input(self):
        paths = filedialog.askopenfilenames(
            title="Select Nessus CSV files",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if paths:
            self._input_paths = list(paths)
            self.path_entry.config(fg=TEXT)
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, "; ".join(paths))

    # ── PROCESSING ────────────────────────────────────────────────────────────

    def _start_processing(self):
        if self.processing:
            return

        path_text = self.path_entry.get().strip()
        if not path_text or path_text == PLACEHOLDER_FILE:
            messagebox.showerror("No file selected", "Please browse and select valid Nessus CSV files.")
            return

        if self._input_paths and "; ".join(self._input_paths) == path_text:
            paths = self._input_paths
        else:
            paths = [p.strip() for p in path_text.split(";") if os.path.isfile(p.strip())]
            
        if not paths:
            messagebox.showerror("No valid files", "Please select valid Nessus CSV files.")
            return

        key    = self.key_entry.get().strip()
        api_key = "" if (not key or key == PLACEHOLDER_KEY) else key
        use_ai  = self.use_ai_var.get()

        if use_ai and not api_key:
            if not messagebox.askyesno(
                "No API key provided",
                "No Gemini API key entered.\n\n"
                "Case 3 will use Plugin Modification Date fallback instead of AI.\n\n"
                "Continue anyway?"
            ):
                return

        self._clear_log()
        self.export_btn.config(state="disabled")
        self.result_rows = []
        for w in self.stats_frame.winfo_children():
            w.destroy()

        self.processing = True
        self.process_btn.config(state="disabled", text="Processing …")
        threading.Thread(
            target=self._run_processing,
            args=(paths, api_key, use_ai),
            daemon=True
        ).start()

    def _run_processing(self, paths: list, api_key: str, use_ai: bool):
        try:
            all_headers = []
            all_rows = []
            for path in paths:
                self._log(f"Reading: {os.path.basename(path)}", "info")
                headers, rows = parse_nessus_csv(path)
                if not all_headers:
                    all_headers = headers
                all_rows.extend(rows)

            self._log(f"Loaded a total of {len(all_rows)} rows.", "info")
            total_before = len(all_rows)

            rows = case1_remove_none_risk(all_rows, self._log)
            removed_none = total_before - len(rows)

            rows = case2_dedup_same_plugin_latest_cve(rows, self._log)

            rows = case3_dedup_same_component_different_version(
                rows, self._log, api_key=api_key, use_ai=use_ai
            )
            removed_dedup = (total_before - removed_none) - len(rows)

            rows = sort_rows(rows, self.sort_mode.get())
            self._log(f"Sorted by {self.sort_mode.get()}.", "ok")

            self.result_rows = rows
            self.result_hdrs = all_headers

            self.after(0, lambda: self._show_stats(
                total_before, removed_none, removed_dedup, len(rows)
            ))
            self._log(f"Done!  {len(rows)} clean rows ready for export.", "ok")
            
            # Auto prompt for export
            self.after(500, self._export_csv)

        except Exception as exc:
            self._log(f"Processing failed: {exc}", "err")
        finally:
            self.processing = False
            self.after(0, lambda: self.process_btn.config(
                state="normal", text="⚙   Process & Clean CSV"))

    def _show_stats(self, total, none_removed, deduped, final):
        for w in self.stats_frame.winfo_children():
            w.destroy()
        for val, lbl, col in [
            (total,        "Total rows",    TEXT),
            (none_removed, "None removed",  WARNING),
            (deduped,      "Deduped",       GEMINI_BLUE),
            (final,        "Final rows",    SUCCESS),
        ]:
            self._stat_card(self.stats_frame, val, lbl, col).pack(side="left", padx=(0, 8))
        if self.result_rows:
            self.export_btn.config(state="normal")

    # ── LOG ───────────────────────────────────────────────────────────────────

    def _log(self, message: str, tag: str = "info"):
        self.log_text.configure(state="normal")
        prefix = {"ok": "✓ ", "warn": "⚠ ", "err": "✗ ", "info": "  "}.get(tag, "  ")
        self.log_text.insert("end", prefix + message + "\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
        self.update_idletasks()

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    # ── EXPORT ────────────────────────────────────────────────────────────────

    def _export_csv(self):
        if not self.result_rows:
            messagebox.showwarning("Nothing to export", "Process a file first.")
            return
        default_name = "nessus_cleaned_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".csv"
        out_path = filedialog.asksaveasfilename(
            title="Save Cleaned CSV",
            defaultextension=".csv",
            initialfile=default_name,
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not out_path:
            return
        try:
            write_csv(self.result_hdrs, self.result_rows, out_path)
            self._log(f"Exported → {out_path}", "ok")
            messagebox.showinfo("Export successful",
                                f"Cleaned CSV saved to:\n{out_path}")
        except Exception as exc:
            self._log(f"Export failed: {exc}", "err")
            messagebox.showerror("Export failed", str(exc))


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = NessusSorterApp()
    app.mainloop()
