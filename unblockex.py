"""
UnBlockEx - Excel Password Removal Tool
Supports:
  1. Direct decryption if password is known
  2. Dictionary attack using a wordlist
  3. Pattern-based brute force (numeric, alphanum, etc.)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import io
import sys
import time
import itertools
import string
import queue
from pathlib import Path

try:
    import msoffcrypto
    MSOFFCRYPTO_AVAILABLE = True
except ImportError:
    MSOFFCRYPTO_AVAILABLE = False

# ─────────────────────────────────────────────
#  Core decryption logic
# ─────────────────────────────────────────────

def try_password(filepath: str, password: str) -> bool:
    """Returns True if the given password opens the file."""
    try:
        with open(filepath, "rb") as f:
            office_file = msoffcrypto.OfficeFile(f)
            if not office_file.is_encrypted():
                return True  # Not encrypted at all
            decrypted = io.BytesIO()
            office_file.load_key(password=password)
            office_file.decrypt(decrypted)
            decrypted.seek(0)
            # Verify it's a valid ZIP (valid OOXML)
            import zipfile
            with zipfile.ZipFile(decrypted) as _z:
                pass
            return True
    except Exception:
        return False


def decrypt_and_save(filepath: str, password: str, out_path: str) -> bool:
    """Decrypt the file with the given password and save to out_path."""
    try:
        with open(filepath, "rb") as f:
            office_file = msoffcrypto.OfficeFile(f)
            decrypted = io.BytesIO()
            office_file.load_key(password=password)
            office_file.decrypt(decrypted)
            decrypted.seek(0)
            with open(out_path, "wb") as out:
                out.write(decrypted.read())
        return True
    except Exception as e:
        return False


def generate_pattern_passwords(charset: str, min_len: int, max_len: int):
    """Yields all combinations of charset from min_len to max_len."""
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


# ─────────────────────────────────────────────
#  GUI Application
# ─────────────────────────────────────────────

class UnBlockExApp:
    COLOR_BG       = "#0f0f1a"
    COLOR_PANEL    = "#1a1a2e"
    COLOR_CARD     = "#16213e"
    COLOR_ACCENT   = "#7c3aed"
    COLOR_ACCENT2  = "#a855f7"
    COLOR_SUCCESS  = "#22c55e"
    COLOR_ERROR    = "#ef4444"
    COLOR_WARNING  = "#f59e0b"
    COLOR_TEXT     = "#e2e8f0"
    COLOR_MUTED    = "#94a3b8"
    COLOR_BORDER   = "#2d2d50"

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("UnBlockEx — Excel Password Remover")
        self.root.geometry("820x700")
        self.root.minsize(720, 600)
        self.root.configure(bg=self.COLOR_BG)

        self._stop_event = threading.Event()
        self._result_queue = queue.Queue()
        self._worker_thread: threading.Thread | None = None

        self._setup_style()
        self._build_ui()

        # Pre-fill default file if present in CWD
        default = Path("2.xlsm")
        if default.exists():
            self.file_var.set(str(default.resolve()))

        self.root.after(100, self._poll_result_queue)

    # ── Style ──────────────────────────────────

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TNotebook",
                        background=self.COLOR_BG,
                        borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=self.COLOR_PANEL,
                        foreground=self.COLOR_MUTED,
                        padding=[18, 8],
                        font=("Segoe UI", 10, "bold"),
                        borderwidth=0)
        style.map("TNotebook.Tab",
                   background=[("selected", self.COLOR_ACCENT)],
                   foreground=[("selected", "white")])

        style.configure("TProgressbar",
                        troughcolor=self.COLOR_BORDER,
                        background=self.COLOR_ACCENT2,
                        borderwidth=0,
                        thickness=8)

        style.configure("Card.TFrame",
                        background=self.COLOR_CARD,
                        relief="flat",
                        borderwidth=0)

    # ── Build UI ───────────────────────────────

    def _build_ui(self):
        # ── Header ──
        header_frame = tk.Frame(self.root, bg=self.COLOR_BG)
        header_frame.pack(fill="x", padx=24, pady=(20, 4))

        tk.Label(header_frame,
                 text="🔓  UnBlockEx",
                 font=("Segoe UI", 22, "bold"),
                 bg=self.COLOR_BG,
                 fg="white").pack(side="left")

        tk.Label(header_frame,
                 text="Excel Password Removal Tool",
                 font=("Segoe UI", 11),
                 bg=self.COLOR_BG,
                 fg=self.COLOR_MUTED).pack(side="left", padx=(12, 0), pady=(6, 0))

        # ── Separator ──
        tk.Frame(self.root, height=1, bg=self.COLOR_BORDER).pack(fill="x", padx=24, pady=(8, 16))

        # ── File picker ──
        self._build_file_picker()

        # ── Tabs ──
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=24, pady=(0, 8))

        self._build_tab_known()
        self._build_tab_dictionary()
        self._build_tab_bruteforce()

        # ── Log ──
        self._build_log_panel()

        # ── Status bar ──
        self._build_status_bar()

    def _build_file_picker(self):
        card = tk.Frame(self.root, bg=self.COLOR_CARD,
                        highlightbackground=self.COLOR_BORDER,
                        highlightthickness=1)
        card.pack(fill="x", padx=24, pady=(0, 12))

        inner = tk.Frame(card, bg=self.COLOR_CARD)
        inner.pack(fill="x", padx=16, pady=12)

        tk.Label(inner, text="📄  Source File",
                 font=("Segoe UI", 10, "bold"),
                 bg=self.COLOR_CARD, fg=self.COLOR_TEXT).pack(anchor="w")

        row = tk.Frame(inner, bg=self.COLOR_CARD)
        row.pack(fill="x", pady=(6, 0))

        self.file_var = tk.StringVar()
        entry = tk.Entry(row, textvariable=self.file_var,
                         font=("Segoe UI", 10),
                         bg="#0d0d1f", fg=self.COLOR_TEXT,
                         insertbackground=self.COLOR_ACCENT2,
                         relief="flat",
                         highlightbackground=self.COLOR_BORDER,
                         highlightcolor=self.COLOR_ACCENT,
                         highlightthickness=1,
                         bd=6)
        entry.pack(side="left", fill="x", expand=True)

        tk.Button(row, text="Browse",
                  font=("Segoe UI", 9, "bold"),
                  bg=self.COLOR_ACCENT, fg="white",
                  activebackground=self.COLOR_ACCENT2,
                  relief="flat", bd=0,
                  padx=16, pady=6,
                  cursor="hand2",
                  command=self._browse_file).pack(side="left", padx=(8, 0))

    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="Select Protected Excel File",
            filetypes=[("Excel files", "*.xlsx *.xlsm *.xls *.xlsb"),
                       ("All files", "*.*")])
        if path:
            self.file_var.set(path)

    # ── Tab: Known Password ────────────────────

    def _build_tab_known(self):
        tab = tk.Frame(self.notebook, bg=self.COLOR_PANEL)
        self.notebook.add(tab, text="🔑  Known Password")

        card = tk.Frame(tab, bg=self.COLOR_CARD,
                        highlightbackground=self.COLOR_BORDER,
                        highlightthickness=1)
        card.pack(fill="both", expand=True, padx=16, pady=16)

        inner = tk.Frame(card, bg=self.COLOR_CARD)
        inner.pack(fill="x", padx=20, pady=24)

        tk.Label(inner, text="Enter the password to decrypt the file:",
                 font=("Segoe UI", 11),
                 bg=self.COLOR_CARD, fg=self.COLOR_TEXT).pack(anchor="w")

        tk.Label(inner, text="The decrypted file will be saved alongside the original without password protection.",
                 font=("Segoe UI", 9),
                 bg=self.COLOR_CARD, fg=self.COLOR_MUTED,
                 wraplength=580, justify="left").pack(anchor="w", pady=(4, 16))

        pw_row = tk.Frame(inner, bg=self.COLOR_CARD)
        pw_row.pack(fill="x")

        tk.Label(pw_row, text="Password:",
                 font=("Segoe UI", 10, "bold"),
                 bg=self.COLOR_CARD, fg=self.COLOR_TEXT).pack(side="left", padx=(0, 8))

        self.known_pw_var = tk.StringVar()
        pw_entry = tk.Entry(pw_row, textvariable=self.known_pw_var,
                            show="●",
                            font=("Segoe UI", 11),
                            bg="#0d0d1f", fg=self.COLOR_TEXT,
                            insertbackground=self.COLOR_ACCENT2,
                            relief="flat",
                            highlightbackground=self.COLOR_BORDER,
                            highlightcolor=self.COLOR_ACCENT,
                            highlightthickness=1,
                            bd=6, width=32)
        pw_entry.pack(side="left")
        pw_entry.bind("<Return>", lambda _: self._run_known())

        show_var = tk.BooleanVar()
        def toggle_show():
            pw_entry.config(show="" if show_var.get() else "●")
        tk.Checkbutton(pw_row, text="Show",
                       variable=show_var, command=toggle_show,
                       bg=self.COLOR_CARD, fg=self.COLOR_MUTED,
                       selectcolor=self.COLOR_CARD,
                       activebackground=self.COLOR_CARD,
                       font=("Segoe UI", 9)).pack(side="left", padx=(12, 0))

        tk.Button(inner, text="🔓  Decrypt & Save",
                  font=("Segoe UI", 11, "bold"),
                  bg=self.COLOR_ACCENT, fg="white",
                  activebackground=self.COLOR_ACCENT2,
                  relief="flat", bd=0,
                  padx=24, pady=10,
                  cursor="hand2",
                  command=self._run_known).pack(anchor="w", pady=(20, 0))

    def _run_known(self):
        filepath = self.file_var.get().strip()
        password = self.known_pw_var.get()
        if not filepath or not os.path.exists(filepath):
            messagebox.showerror("Error", "Please select a valid Excel file.")
            return
        if not password:
            messagebox.showerror("Error", "Please enter the password.")
            return

        self._log(f"▶  Trying password on: {filepath}")
        self._set_status("Testing password...", self.COLOR_WARNING)

        def worker():
            if try_password(filepath, password):
                out = self._make_output_path(filepath)
                if decrypt_and_save(filepath, password, out):
                    self._result_queue.put(("success", f"✅  Password correct! Saved to:\n{out}"))
                else:
                    self._result_queue.put(("error", "❌  Decryption failed while saving."))
            else:
                self._result_queue.put(("error", "❌  Incorrect password."))

        threading.Thread(target=worker, daemon=True).start()

    # ── Tab: Dictionary Attack ─────────────────

    def _build_tab_dictionary(self):
        tab = tk.Frame(self.notebook, bg=self.COLOR_PANEL)
        self.notebook.add(tab, text="📖  Dictionary Attack")

        card = tk.Frame(tab, bg=self.COLOR_CARD,
                        highlightbackground=self.COLOR_BORDER,
                        highlightthickness=1)
        card.pack(fill="both", expand=True, padx=16, pady=16)

        inner = tk.Frame(card, bg=self.COLOR_CARD)
        inner.pack(fill="x", padx=20, pady=20)

        tk.Label(inner, text="Try passwords from a wordlist file (one password per line).",
                 font=("Segoe UI", 11),
                 bg=self.COLOR_CARD, fg=self.COLOR_TEXT).pack(anchor="w")
        tk.Label(inner,
                 text="Useful when you remember approximate hints (e.g. used RockYou, company wordlists, etc.)",
                 font=("Segoe UI", 9),
                 bg=self.COLOR_CARD, fg=self.COLOR_MUTED).pack(anchor="w", pady=(2, 12))

        # Wordlist file row
        row = tk.Frame(inner, bg=self.COLOR_CARD)
        row.pack(fill="x")

        tk.Label(row, text="Wordlist:", font=("Segoe UI", 10, "bold"),
                 bg=self.COLOR_CARD, fg=self.COLOR_TEXT).pack(side="left", padx=(0, 8))

        self.dict_file_var = tk.StringVar()
        tk.Entry(row, textvariable=self.dict_file_var,
                 font=("Segoe UI", 10),
                 bg="#0d0d1f", fg=self.COLOR_TEXT,
                 insertbackground=self.COLOR_ACCENT2,
                 relief="flat",
                 highlightbackground=self.COLOR_BORDER,
                 highlightcolor=self.COLOR_ACCENT,
                 highlightthickness=1,
                 bd=6).pack(side="left", fill="x", expand=True)

        tk.Button(row, text="Browse",
                  font=("Segoe UI", 9, "bold"),
                  bg="#334155", fg="white",
                  relief="flat", bd=0,
                  padx=14, pady=5,
                  cursor="hand2",
                  command=lambda: self._browse_wordlist()).pack(side="left", padx=(8, 0))

        # Custom hints section
        hints_frame = tk.Frame(inner, bg=self.COLOR_CARD)
        hints_frame.pack(fill="x", pady=(16, 0))

        tk.Label(hints_frame, text="Or paste custom password hints (one per line):",
                 font=("Segoe UI", 10, "bold"),
                 bg=self.COLOR_CARD, fg=self.COLOR_TEXT).pack(anchor="w")

        self.hints_text = tk.Text(hints_frame,
                                  height=5,
                                  font=("Consolas", 10),
                                  bg="#0d0d1f", fg=self.COLOR_TEXT,
                                  insertbackground=self.COLOR_ACCENT2,
                                  relief="flat",
                                  highlightbackground=self.COLOR_BORDER,
                                  highlightcolor=self.COLOR_ACCENT,
                                  highlightthickness=1,
                                  bd=6)
        self.hints_text.pack(fill="x", pady=(6, 0))
        self.hints_text.insert("1.0", "# Enter your guesses here, one per line\n# Example:\n# trabajo2020\n# miarchivo123")

        # Progress bar
        self.dict_progress_var = tk.DoubleVar()
        self.dict_progress_label = tk.Label(inner, text="",
                                            font=("Segoe UI", 9),
                                            bg=self.COLOR_CARD, fg=self.COLOR_MUTED)
        self.dict_progress_label.pack(anchor="w", pady=(14, 2))

        self.dict_progress = ttk.Progressbar(inner,
                                              variable=self.dict_progress_var,
                                              maximum=100)
        self.dict_progress.pack(fill="x")

        # Buttons
        btn_row = tk.Frame(inner, bg=self.COLOR_CARD)
        btn_row.pack(fill="x", pady=(14, 0))

        tk.Button(btn_row, text="▶  Start Dictionary Attack",
                  font=("Segoe UI", 11, "bold"),
                  bg=self.COLOR_ACCENT, fg="white",
                  activebackground=self.COLOR_ACCENT2,
                  relief="flat", bd=0,
                  padx=24, pady=10,
                  cursor="hand2",
                  command=self._run_dictionary).pack(side="left")

        tk.Button(btn_row, text="⏹  Stop",
                  font=("Segoe UI", 10),
                  bg="#334155", fg="white",
                  relief="flat", bd=0,
                  padx=16, pady=10,
                  cursor="hand2",
                  command=self._stop_attack).pack(side="left", padx=(12, 0))

    def _browse_wordlist(self):
        path = filedialog.askopenfilename(
            title="Select Wordlist file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.dict_file_var.set(path)

    def _run_dictionary(self):
        filepath = self.file_var.get().strip()
        if not filepath or not os.path.exists(filepath):
            messagebox.showerror("Error", "Please select a valid Excel file.")
            return

        # Collect passwords
        passwords = []
        hints_raw = self.hints_text.get("1.0", "end").strip()
        for line in hints_raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                passwords.append(line)

        wordlist_path = self.dict_file_var.get().strip()
        if wordlist_path and os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        pw = line.strip()
                        if pw:
                            passwords.append(pw)
            except Exception as e:
                self._log(f"⚠ Could not read wordlist: {e}")

        if not passwords:
            messagebox.showwarning("No passwords", "Please provide hints or a wordlist file.")
            return

        passwords = list(dict.fromkeys(passwords))  # deduplicate
        self._start_cracking(filepath, iter(passwords), len(passwords), mode="dict")

    # ── Tab: Brute Force ──────────────────────

    def _build_tab_bruteforce(self):
        tab = tk.Frame(self.notebook, bg=self.COLOR_PANEL)
        self.notebook.add(tab, text="⚡  Brute Force")

        card = tk.Frame(tab, bg=self.COLOR_CARD,
                        highlightbackground=self.COLOR_BORDER,
                        highlightthickness=1)
        card.pack(fill="both", expand=True, padx=16, pady=16)

        inner = tk.Frame(card, bg=self.COLOR_CARD)
        inner.pack(fill="x", padx=20, pady=20)

        tk.Label(inner, text="Brute-force all combinations up to a given length.",
                 font=("Segoe UI", 11),
                 bg=self.COLOR_CARD, fg=self.COLOR_TEXT).pack(anchor="w")
        tk.Label(inner,
                 text="⚠  Warning: This can take a very long time for passwords > 4–5 characters.",
                 font=("Segoe UI", 9),
                 bg=self.COLOR_CARD, fg=self.COLOR_WARNING).pack(anchor="w", pady=(2, 14))

        # Charset options
        charset_frame = tk.LabelFrame(inner, text="  Character Set  ",
                                      font=("Segoe UI", 9, "bold"),
                                      bg=self.COLOR_CARD, fg=self.COLOR_MUTED,
                                      bd=1, highlightbackground=self.COLOR_BORDER,
                                      relief="groove")
        charset_frame.pack(fill="x")

        options = [
            ("Digits only (0-9)", string.digits),
            ("Lowercase letters (a-z)", string.ascii_lowercase),
            ("Uppercase letters (A-Z)", string.ascii_uppercase),
            ("Letters + digits", string.ascii_letters + string.digits),
            ("All printable (slow!)", string.printable.strip()),
            ("Custom charset →", None),
        ]

        self.charset_var = tk.StringVar(value=string.digits)
        self.charset_radio_var = tk.StringVar(value=options[0][0])

        cf_inner = tk.Frame(charset_frame, bg=self.COLOR_CARD)
        cf_inner.pack(padx=12, pady=8, fill="x")

        for label, val in options:
            row = tk.Frame(cf_inner, bg=self.COLOR_CARD)
            row.pack(anchor="w")
            rb = tk.Radiobutton(row, text=label,
                                value=label,
                                variable=self.charset_radio_var,
                                bg=self.COLOR_CARD,
                                fg=self.COLOR_TEXT,
                                selectcolor=self.COLOR_PANEL,
                                activebackground=self.COLOR_CARD,
                                font=("Segoe UI", 10),
                                command=lambda v=val, l=label: self._on_charset_select(v, l))
            rb.pack(side="left")

        # Custom charset entry
        cust_row = tk.Frame(cf_inner, bg=self.COLOR_CARD)
        cust_row.pack(fill="x", pady=(4, 0))
        tk.Label(cust_row, text="Custom:", font=("Segoe UI", 9, "bold"),
                 bg=self.COLOR_CARD, fg=self.COLOR_MUTED).pack(side="left", padx=(20, 6))
        self.custom_charset_var = tk.StringVar(value="0123456789abcdef")
        tk.Entry(cust_row, textvariable=self.custom_charset_var,
                 font=("Consolas", 10),
                 bg="#0d0d1f", fg=self.COLOR_TEXT,
                 insertbackground=self.COLOR_ACCENT2,
                 relief="flat",
                 highlightbackground=self.COLOR_BORDER,
                 highlightthickness=1,
                 bd=6, width=30).pack(side="left")

        # Length options
        len_row = tk.Frame(inner, bg=self.COLOR_CARD)
        len_row.pack(fill="x", pady=(14, 0))

        tk.Label(len_row, text="Min length:", font=("Segoe UI", 10, "bold"),
                 bg=self.COLOR_CARD, fg=self.COLOR_TEXT).pack(side="left")
        self.bf_min_var = tk.IntVar(value=1)
        tk.Spinbox(len_row, from_=1, to=10, textvariable=self.bf_min_var,
                   width=4, font=("Segoe UI", 10),
                   bg="#0d0d1f", fg=self.COLOR_TEXT, relief="flat",
                   buttonbackground=self.COLOR_BORDER,
                   insertbackground=self.COLOR_ACCENT2).pack(side="left", padx=(6, 24))

        tk.Label(len_row, text="Max length:", font=("Segoe UI", 10, "bold"),
                 bg=self.COLOR_CARD, fg=self.COLOR_TEXT).pack(side="left")
        self.bf_max_var = tk.IntVar(value=4)
        tk.Spinbox(len_row, from_=1, to=10, textvariable=self.bf_max_var,
                   width=4, font=("Segoe UI", 10),
                   bg="#0d0d1f", fg=self.COLOR_TEXT, relief="flat",
                   buttonbackground=self.COLOR_BORDER,
                   insertbackground=self.COLOR_ACCENT2).pack(side="left", padx=(6, 0))

        # Estimate label
        self.bf_estimate_label = tk.Label(inner, text="",
                                          font=("Segoe UI", 9),
                                          bg=self.COLOR_CARD, fg=self.COLOR_MUTED)
        self.bf_estimate_label.pack(anchor="w", pady=(10, 0))

        self.bf_min_var.trace_add("write", self._update_bf_estimate)
        self.bf_max_var.trace_add("write", self._update_bf_estimate)
        self._on_charset_select(string.digits, options[0][0])

        # Progress
        self.bf_progress_label = tk.Label(inner, text="",
                                          font=("Segoe UI", 9),
                                          bg=self.COLOR_CARD, fg=self.COLOR_MUTED)
        self.bf_progress_label.pack(anchor="w", pady=(10, 2))

        self.bf_progress_var = tk.DoubleVar()
        self.bf_progress = ttk.Progressbar(inner, variable=self.bf_progress_var, maximum=100)
        self.bf_progress.pack(fill="x")

        # Buttons
        btn_row = tk.Frame(inner, bg=self.COLOR_CARD)
        btn_row.pack(fill="x", pady=(14, 0))

        tk.Button(btn_row, text="▶  Start Brute Force",
                  font=("Segoe UI", 11, "bold"),
                  bg=self.COLOR_ACCENT, fg="white",
                  activebackground=self.COLOR_ACCENT2,
                  relief="flat", bd=0,
                  padx=24, pady=10,
                  cursor="hand2",
                  command=self._run_bruteforce).pack(side="left")

        tk.Button(btn_row, text="⏹  Stop",
                  font=("Segoe UI", 10),
                  bg="#334155", fg="white",
                  relief="flat", bd=0,
                  padx=16, pady=10,
                  cursor="hand2",
                  command=self._stop_attack).pack(side="left", padx=(12, 0))

    def _on_charset_select(self, val, label):
        if val is None:
            self.charset_var.set(self.custom_charset_var.get())
        else:
            self.charset_var.set(val)
        self._update_bf_estimate()

    def _update_bf_estimate(self, *_):
        try:
            charset = self.charset_var.get() or self.custom_charset_var.get()
            n = len(set(charset))
            min_l = self.bf_min_var.get()
            max_l = self.bf_max_var.get()
            total = sum(n**i for i in range(min_l, max_l + 1))
            if total > 1_000_000_000:
                label = f"~{total:,} combinations – This will take extremely long (billions)!"
                color = self.COLOR_ERROR
            elif total > 10_000_000:
                label = f"~{total:,} combinations – May take several minutes to hours."
                color = self.COLOR_WARNING
            else:
                label = f"~{total:,} combinations"
                color = self.COLOR_MUTED
            self.bf_estimate_label.config(text=label, fg=color)
        except Exception:
            pass

    def _run_bruteforce(self):
        filepath = self.file_var.get().strip()
        if not filepath or not os.path.exists(filepath):
            messagebox.showerror("Error", "Please select a valid Excel file.")
            return

        charset_label = self.charset_radio_var.get()
        if "Custom" in charset_label:
            charset = self.custom_charset_var.get()
        else:
            charset = self.charset_var.get()

        if not charset:
            messagebox.showerror("Error", "Character set cannot be empty.")
            return

        charset = "".join(sorted(set(charset)))  # deduplicate
        min_l = self.bf_min_var.get()
        max_l = self.bf_max_var.get()

        n = len(charset)
        total = sum(n**i for i in range(min_l, max_l + 1))
        gen = generate_pattern_passwords(charset, min_l, max_l)
        self._start_cracking(filepath, gen, total, mode="bf")

    # ── Log panel ─────────────────────────────

    def _build_log_panel(self):
        log_frame = tk.Frame(self.root, bg=self.COLOR_BG)
        log_frame.pack(fill="x", padx=24, pady=(0, 4))

        header_row = tk.Frame(log_frame, bg=self.COLOR_BG)
        header_row.pack(fill="x")

        tk.Label(header_row, text="📋  Activity Log",
                 font=("Segoe UI", 10, "bold"),
                 bg=self.COLOR_BG, fg=self.COLOR_TEXT).pack(side="left")

        tk.Button(header_row, text="Clear",
                  font=("Segoe UI", 8),
                  bg="#334155", fg=self.COLOR_MUTED,
                  relief="flat", bd=0,
                  padx=8, pady=2,
                  cursor="hand2",
                  command=self._clear_log).pack(side="right")

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=6,
            font=("Consolas", 9),
            bg="#0a0a14",
            fg=self.COLOR_TEXT,
            insertbackground=self.COLOR_ACCENT2,
            relief="flat",
            highlightbackground=self.COLOR_BORDER,
            highlightthickness=1,
            bd=0,
            state="disabled")
        self.log_text.pack(fill="x", pady=(6, 0))

    def _log(self, msg: str):
        def _do():
            self.log_text.config(state="normal")
            self.log_text.insert("end", f"{time.strftime('%H:%M:%S')}  {msg}\n")
            self.log_text.see("end")
            self.log_text.config(state="disabled")
        self.root.after(0, _do)

    def _clear_log(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

    # ── Status bar ────────────────────────────

    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg=self.COLOR_PANEL,
                       highlightbackground=self.COLOR_BORDER,
                       highlightthickness=1)
        bar.pack(fill="x", side="bottom")

        self.status_var = tk.StringVar(value="Ready")
        self.status_label = tk.Label(bar,
                                     textvariable=self.status_var,
                                     font=("Segoe UI", 9),
                                     bg=self.COLOR_PANEL,
                                     fg=self.COLOR_MUTED,
                                     anchor="w")
        self.status_label.pack(side="left", padx=16, pady=6)

        if not MSOFFCRYPTO_AVAILABLE:
            tk.Label(bar, text="⚠ msoffcrypto-tool not installed",
                     font=("Segoe UI", 9, "bold"),
                     bg=self.COLOR_PANEL, fg=self.COLOR_ERROR).pack(side="right", padx=16)

    def _set_status(self, msg: str, color: str = None):
        color = color or self.COLOR_MUTED
        def _do():
            self.status_var.set(msg)
            self.status_label.config(fg=color)
        self.root.after(0, _do)

    # ── Cracking engine ───────────────────────

    def _stop_attack(self):
        self._stop_event.set()
        self._log("⏹  Attack stopped by user.")
        self._set_status("Stopped.", self.COLOR_WARNING)

    def _start_cracking(self, filepath: str, gen, total: int, mode: str):
        if self._worker_thread and self._worker_thread.is_alive():
            messagebox.showwarning("Running", "An attack is already in progress. Stop it first.")
            return

        self._stop_event.clear()
        self._log(f"▶  Starting {'dictionary' if mode == 'dict' else 'brute force'} attack on: {os.path.basename(filepath)}")
        self._log(f"   Total candidates: {total:,}")
        self._set_status("Running attack...", self.COLOR_WARNING)

        def worker():
            checked = 0
            last_update = time.time()
            chunk_size = 50  # passwords per batch before UI update

            for password in gen:
                if self._stop_event.is_set():
                    break

                if try_password(filepath, password):
                    out = self._make_output_path(filepath)
                    if decrypt_and_save(filepath, password, out):
                        self._result_queue.put(("success",
                            f"✅  PASSWORD FOUND: {password!r}\n\nDecrypted file saved to:\n{out}",
                            password))
                    else:
                        self._result_queue.put(("error", f"Password found ({password!r}) but saving failed."))
                    return

                checked += 1
                now = time.time()
                if now - last_update > 0.3:  # update every 300ms
                    pct = (checked / total * 100) if total > 0 else 0
                    speed = checked / max(now - (time.time() - 0.3), 0.001)
                    self._update_progress(mode, checked, total, pct, password)
                    last_update = now

            self._result_queue.put(("notfound", f"❌  Password not found after trying {checked:,} candidates."))

        self._worker_thread = threading.Thread(target=worker, daemon=True)
        self._worker_thread.start()

    def _update_progress(self, mode: str, checked: int, total: int, pct: float, current: str):
        def _do():
            label_text = f"Trying: {current!r}  |  {checked:,} / {total:,}  ({pct:.1f}%)"
            if mode == "dict":
                self.dict_progress_label.config(text=label_text)
                self.dict_progress_var.set(pct)
            else:
                self.bf_progress_label.config(text=label_text)
                self.bf_progress_var.set(pct)
        self.root.after(0, _do)

    def _poll_result_queue(self):
        """Poll for results from worker thread and update UI."""
        try:
            while True:
                item = self._result_queue.get_nowait()
                kind = item[0]
                msg  = item[1]
                pw   = item[2] if len(item) > 2 else None

                if kind == "success":
                    self._log(msg)
                    self._set_status("✅  Success!", self.COLOR_SUCCESS)
                    messagebox.showinfo("Success! 🎉", msg)
                elif kind == "error":
                    self._log(msg)
                    self._set_status("Error.", self.COLOR_ERROR)
                    messagebox.showerror("Failed", msg)
                elif kind == "notfound":
                    self._log(msg)
                    self._set_status("Password not found.", self.COLOR_ERROR)
                    messagebox.showwarning("Not Found", msg)
        except queue.Empty:
            pass

        self.root.after(150, self._poll_result_queue)

    # ── Helpers ───────────────────────────────

    def _make_output_path(self, filepath: str) -> str:
        p = Path(filepath)
        return str(p.parent / f"{p.stem}_UNLOCKED{p.suffix}")


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────

def main():
    if not MSOFFCRYPTO_AVAILABLE:
        print("ERROR: msoffcrypto-tool is not installed.")
        print("Run: pip install msoffcrypto-tool")
        sys.exit(1)

    root = tk.Tk()
    app = UnBlockExApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
