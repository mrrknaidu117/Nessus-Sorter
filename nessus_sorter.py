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

import json
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime

# Import modular processing pipelines and helpers
from sorter_ip import validate_gemini_key, run_ip_sorting_pipeline, write_csv
from sorter_name import run_name_sorting_pipeline


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
        self._make_btn(fr, "Add File(s) …", self._browse_input, ACCENT).pack(side="left", padx=(8, 0))
        self._make_btn(fr, "Clear", self._clear_input, DANGER).pack(side="left", padx=(8, 0))

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

        self.open_folder_btn = self._make_btn(
            bot, "📂   Open Folder",
            self._open_export_folder, ACCENT,
            font=("Segoe UI", 11, "bold"), pady=10
        )
        self.open_folder_btn.pack(side="right", padx=(0, 8))
        self.open_folder_btn.config(state="disabled")

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
            # Parse existing paths from the text entry to preserve any manual edits
            current_text = self.path_entry.get().strip()
            if current_text and current_text != PLACEHOLDER_FILE:
                current_paths = [p.strip() for p in current_text.split(";") if p.strip()]
            else:
                current_paths = []

            # Append new paths to the current ones
            for p in paths:
                if p not in current_paths:
                    current_paths.append(p)

            self._input_paths = current_paths
            self.path_entry.config(fg=TEXT)
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, "; ".join(self._input_paths))

    def _clear_input(self):
        self._input_paths = []
        self.path_entry.delete(0, "end")
        self.path_entry.config(fg=TEXT_MUTED)
        self.path_entry.insert(0, PLACEHOLDER_FILE)

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

        paths = list(dict.fromkeys(paths))
            
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
        self.open_folder_btn.config(state="disabled")
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
            sort_mode = self.sort_mode.get()
            if sort_mode == "ip":
                headers, rows, total, none_removed, deduped = run_ip_sorting_pipeline(
                    paths, api_key, use_ai, self._log
                )
            else:
                headers, rows, total, none_removed, deduped = run_name_sorting_pipeline(
                    paths, api_key, use_ai, self._log
                )

            self.result_rows = rows
            self.result_hdrs = headers

            self.after(0, lambda: self._show_stats(
                total, none_removed, deduped, len(rows)
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

        # Write to log file
        log_path = os.path.join(os.path.dirname(__file__), "nessus_sorter.log")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_prefix = {"ok": "[SUCCESS] ", "warn": "[WARNING] ", "err": "[ERROR]   ", "info": "[INFO]    "}.get(tag, "[INFO]    ")
        try:
            with open(log_path, "a", encoding="utf-8") as lf:
                lf.write(f"{timestamp} {log_prefix}{message}\n")
        except Exception:
            pass

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
            
            # Save export folder and enable open folder button
            self.last_export_dir = os.path.dirname(out_path)
            self.open_folder_btn.config(state="normal")
            
            messagebox.showinfo("Export successful",
                                f"Cleaned CSV saved to:\n{out_path}")
        except Exception as exc:
            self._log(f"Export failed: {exc}", "err")
            messagebox.showerror("Export failed", str(exc))

    def _open_export_folder(self):
        if hasattr(self, "last_export_dir") and self.last_export_dir:
            try:
                os.startfile(self.last_export_dir)
            except Exception as exc:
                messagebox.showerror("Error", f"Could not open folder: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = NessusSorterApp()
    app.mainloop()
