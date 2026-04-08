"""
vault32 GUI application.
"""

import json
import os
import shutil
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, ttk

from vl_crypto import (
    INACTIVITY_LOCK_SECONDS,
    SECURITY_LABELS,
    SECURITY_PROFILES,
    lock_folder,
    unlock_file,
)


BG = "#f6f8fb"
SURFACE = "#ffffff"
BORDER = "#d8dee8"
ACCENT = "#2e7d32"
TEXT = "#1f2937"
SUBTEXT = "#5f6b7a"
DANGER = "#c62828"
SUCCESS = "#2e7d32"

FONT_MONO = ("Consolas", 10)
FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_LABEL = ("Segoe UI", 10)
FONT_BTN = ("Segoe UI", 10, "bold")
FONT_SMALL = ("Segoe UI", 9)


class VaultLockApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("vault32")
        self.resizable(False, False)
        self.configure(bg=BG)

        # Use the new vault32 paths, but keep legacy VaultLock locations if already in use.
        default_vault_dir = os.path.join(os.path.expanduser("~"), "vault32Private")
        legacy_vault_dir = os.path.join(os.path.expanduser("~"), "VaultLockPrivate")
        default_config_path = os.path.join(os.path.expanduser("~"), ".vault32_settings.json")
        legacy_config_path = os.path.join(os.path.expanduser("~"), ".vaultlock_settings.json")

        self._vault_dir = default_vault_dir
        self._config_path = default_config_path
        if (
            not os.path.exists(default_vault_dir)
            and not os.path.exists(default_vault_dir + ".locked")
            and (os.path.exists(legacy_vault_dir) or os.path.exists(legacy_vault_dir + ".locked"))
        ):
            self._vault_dir = legacy_vault_dir
        if not os.path.exists(default_config_path) and os.path.exists(legacy_config_path):
            self._config_path = legacy_config_path

        self._vault_locked = self._vault_dir + ".locked"
        self._vault_password = None
        self._vault_unlocked = False
        self._vault_items = []
        self._last_activity_ts = time.time()
        self._inactivity_lock_seconds = INACTIVITY_LOCK_SECONDS
        self._security_profile = "fast"
        self._kdf_iterations = SECURITY_PROFILES[self._security_profile]

        self._load_settings()

        self._center()
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._setup_activity_tracking()
        self.after(5000, self._check_inactivity_autolock)
        self._startup_locked_path = self._get_startup_locked_path()
        if self._startup_locked_path:
            self.after(150, self._startup_unlock_tool_flow)
        else:
            self.after(150, self._startup_vault_flow)

    def _get_startup_locked_path(self):
        # Supports launching from Windows file association: vault32.exe "file.locked"
        for arg in sys.argv[1:]:
            candidate = os.path.abspath(arg)
            if os.path.isfile(candidate) and candidate.lower().endswith(".locked"):
                return candidate
        return None

    def _setup_activity_tracking(self):
        for event_name in ("<Any-KeyPress>", "<Any-Button>", "<MouseWheel>"):
            self.bind_all(event_name, self._touch_activity)

    def _touch_activity(self, _event=None):
        self._last_activity_ts = time.time()

    def _check_inactivity_autolock(self):
        try:
            if self._vault_unlocked:
                idle_seconds = time.time() - self._last_activity_ts
                if idle_seconds >= self._inactivity_lock_seconds:
                    locked = self._lock_private_vault(silent=True)
                    if locked:
                        mins = self._inactivity_lock_seconds // 60
                        self._set_status(f"Auto-locked after {mins} minutes of inactivity.", SUCCESS)
                        self._alert_warning("Auto-locked", f"Private vault was locked after {mins} minutes of inactivity.")
                        self._touch_activity()
        finally:
            self.after(5000, self._check_inactivity_autolock)

    def _load_settings(self):
        if not os.path.isfile(self._config_path):
            return
        try:
            with open(self._config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            minutes = int(data.get("auto_lock_minutes", INACTIVITY_LOCK_SECONDS // 60))
            minutes = max(1, min(240, minutes))
            self._inactivity_lock_seconds = minutes * 60
            profile = str(data.get("security_profile", self._security_profile)).lower()
            if profile in SECURITY_PROFILES:
                self._security_profile = profile
                self._kdf_iterations = SECURITY_PROFILES[profile]
        except Exception:
            pass

    def _save_settings(self):
        data = {
            "auto_lock_minutes": self._inactivity_lock_seconds // 60,
            "security_profile": self._security_profile,
        }
        try:
            with open(self._config_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self._alert_error("Settings", f"Could not save settings:\n{e}")

    def _center(self):
        w, h = 700, 680
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self):
        # ── Header ──
        hdr = tk.Frame(self, bg=BG, padx=24, pady=20)
        hdr.pack(fill="x")
        tk.Label(hdr, text="VAULT32", font=FONT_TITLE,
                 fg=ACCENT, bg=BG).pack(side="left")
        tk.Label(hdr, text="v1.1", font=FONT_SMALL,
                 fg=SUBTEXT, bg=BG).pack(side="left", padx=(8, 0), pady=(6, 0))

        # ── Divider ──
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # ── Tab strip ──
        self._tab = tk.StringVar(value="vault")
        tab_row = tk.Frame(self, bg=SURFACE)
        tab_row.pack(fill="x")
        for label, val in [
            ("  PRIVATE VAULT  ", "vault"),
            ("  SETTINGS  ", "settings"),
            ("  TOOL: LOCK FOLDER  ", "lock"),
            ("  TOOL: UNLOCK FILE  ", "unlock"),
        ]:
            tk.Radiobutton(
                tab_row, text=label, variable=self._tab, value=val,
                command=self._switch_tab,
                font=FONT_BTN, fg=TEXT, bg=SURFACE,
                activeforeground=ACCENT, activebackground=SURFACE,
                selectcolor=BG, relief="flat", bd=0,
                indicatoron=False, padx=10, pady=10,
                highlightthickness=0
            ).pack(side="left")

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # ── Body frames ──
        self._vault_frame = self._build_vault_panel()
        self._settings_frame = self._build_settings_panel()
        self._lock_frame = self._build_lock_panel()
        self._unlock_frame = self._build_unlock_panel()
        self._switch_tab()
        self._update_vault_action_states()

        # ── Progress ──
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        prog_area = tk.Frame(self, bg=BG, padx=24, pady=14)
        prog_area.pack(fill="x")

        self._status = tk.StringVar(value="Ready.")
        self._status_lbl = tk.Label(prog_area, textvariable=self._status,
                        font=FONT_LABEL, fg=SUBTEXT, bg=BG,
                        anchor="w")
        self._status_lbl.pack(fill="x")

        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("Vault.Horizontal.TProgressbar",
                         troughcolor=SURFACE, background=ACCENT,
                         bordercolor=BORDER, lightcolor=ACCENT,
                         darkcolor=ACCENT, thickness=6)
        self._prog = ttk.Progressbar(prog_area, style="Vault.Horizontal.TProgressbar",
                                      orient="horizontal", length=472, mode="determinate")
        self._prog.pack(pady=(6, 0))

        # ── Footer ──
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        ft = tk.Frame(self, bg=BG, padx=24, pady=8)
        ft.pack(fill="x")
        self._crypto_line = tk.StringVar()
        tk.Label(ft, textvariable=self._crypto_line,
             font=FONT_SMALL, fg=SUBTEXT, bg=BG).pack(side="left")
        self._refresh_crypto_footer()

    def _build_vault_panel(self):
        frame = tk.Frame(self, bg=BG, padx=24, pady=20)

        tk.Label(frame, text="DEFAULT PRIVATE VAULT", font=FONT_LABEL,
                 fg=SUBTEXT, bg=BG, anchor="w").pack(fill="x")
        row1 = tk.Frame(frame, bg=BG)
        row1.pack(fill="x", pady=(4, 12))

        self._vault_path = tk.StringVar(value=self._vault_dir)
        tk.Entry(row1, textvariable=self._vault_path, state="readonly", font=FONT_MONO,
                 readonlybackground=SURFACE, fg=TEXT,
                 relief="flat", bd=0, highlightthickness=1,
                 highlightbackground=BORDER, highlightcolor=ACCENT,
                 width=60).pack(side="left", ipady=7, padx=(0, 8), fill="x", expand=True)
        self._btn(row1, "🗂 OPEN", self._open_vault_folder).pack(side="left")

        self._vault_state = tk.StringVar(value="State: Locked")
        self._vault_state_lbl = tk.Label(
            frame,
            textvariable=self._vault_state,
            font=FONT_SMALL,
            fg=SUBTEXT,
            bg=BG,
            anchor="w",
        )
        self._vault_state_lbl.pack(fill="x", pady=(0, 10))

        row2 = tk.Frame(frame, bg=BG)
        row2.pack(fill="x", pady=(0, 6))
        self._btn_unlock_vault = self._btn(row2, "🔓 UNLOCK", self._manual_unlock_vault)
        self._btn_unlock_vault.pack(side="left", padx=(0, 8))
        self._btn_lock_vault = self._btn(row2, "🔒 LOCK", self._manual_lock_vault, accent=True)
        self._btn_lock_vault.pack(side="left", padx=(0, 8))
        self._btn(row2, "📄 ADD FILE", self._vault_add_files).pack(side="left", padx=(0, 8))
        self._btn(row2, "📁 ADD FOLDER", self._vault_add_folder).pack(side="left", padx=(0, 8))

        row2b = tk.Frame(frame, bg=BG)
        row2b.pack(fill="x", pady=(0, 12))
        self._btn(row2b, "📂 OPEN ITEM", self._vault_open_selected).pack(side="left", padx=(0, 8))
        self._btn(row2b, "✏ RENAME", self._vault_rename_selected).pack(side="left", padx=(0, 8))
        self._btn(row2b, "🗑 REMOVE", self._vault_remove_selected).pack(side="left", padx=(0, 8))
        self._btn(row2b, "↻ REFRESH", self._refresh_vault_list).pack(side="left")

        task = tk.Frame(frame, bg="#f8fafc", highlightthickness=1, highlightbackground=BORDER)
        task.pack(fill="x", pady=(0, 12))
        task_row = tk.Frame(task, bg="#f8fafc")
        task_row.pack(fill="x")
        self._task_msg = tk.StringVar(value="Ready. No active operation.")
        tk.Label(task_row, textvariable=self._task_msg, font=FONT_SMALL,
                 fg=SUBTEXT, bg="#f8fafc", anchor="w", padx=10, pady=6).pack(side="left", fill="x", expand=True)
        self._task_pct = tk.StringVar(value="0%")
        tk.Label(task_row, textvariable=self._task_pct, font=FONT_SMALL,
                 fg=SUBTEXT, bg="#f8fafc", anchor="e", padx=10, pady=6).pack(side="right")

        tk.Label(frame, text="FILES IN PRIVATE VAULT", font=FONT_LABEL,
                 fg=SUBTEXT, bg=BG, anchor="w").pack(fill="x")

        list_wrap = tk.Frame(frame, bg=SURFACE, highlightthickness=1, highlightbackground=BORDER)
        list_wrap.pack(fill="both", expand=True, pady=(6, 12))

        self._vault_list = tk.Listbox(
            list_wrap,
            bg=SURFACE,
            fg=TEXT,
            selectbackground=ACCENT,
            selectforeground=BG,
            font=FONT_MONO,
            relief="flat",
            bd=0,
            highlightthickness=0,
            activestyle="none",
            height=14,
        )
        scroll = tk.Scrollbar(list_wrap, orient="vertical", command=self._vault_list.yview)
        self._vault_list.configure(yscrollcommand=scroll.set)
        self._vault_list.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        scroll.pack(side="right", fill="y", pady=6)
        self._vault_list.bind("<Double-Button-1>", self._vault_open_selected)
        self._vault_list.bind("<<ListboxSelect>>", self._on_vault_selection_changed)

        details = tk.Frame(frame, bg="#f8fafc", highlightthickness=1, highlightbackground=BORDER)
        details.pack(fill="x", pady=(0, 12))
        tk.Label(details, text="SELECTED ITEM DETAILS", font=FONT_SMALL,
                 fg=SUBTEXT, bg="#f8fafc", anchor="w", padx=10, pady=6).pack(fill="x")

        self._details_name = tk.StringVar(value="Name: -")
        self._details_type = tk.StringVar(value="Type: -")
        self._details_size = tk.StringVar(value="Size: -")
        self._details_mod = tk.StringVar(value="Modified: -")
        self._details_path = tk.StringVar(value="Path: -")

        tk.Label(details, textvariable=self._details_name, font=FONT_SMALL,
                 fg=TEXT, bg="#f8fafc", anchor="w", padx=10).pack(fill="x")
        tk.Label(details, textvariable=self._details_type, font=FONT_SMALL,
                 fg=TEXT, bg="#f8fafc", anchor="w", padx=10).pack(fill="x")
        tk.Label(details, textvariable=self._details_size, font=FONT_SMALL,
                 fg=TEXT, bg="#f8fafc", anchor="w", padx=10).pack(fill="x")
        tk.Label(details, textvariable=self._details_mod, font=FONT_SMALL,
                 fg=TEXT, bg="#f8fafc", anchor="w", padx=10).pack(fill="x")
        tk.Label(details, textvariable=self._details_path, font=FONT_SMALL,
                 fg=SUBTEXT, bg="#f8fafc", anchor="w", justify="left", wraplength=620,
                 padx=10, pady=0).pack(fill="x", pady=(0, 8))

        note = tk.Frame(frame, bg="#fff7d6", highlightthickness=1,
                        highlightbackground="#e8d594")
        note.pack(fill="x", pady=(12, 0))
        tk.Label(note, text="The private vault auto-locks when you exit the app.\n"
                            "Use TOOL tabs only when you want manual multi-folder operations.",
                 font=FONT_SMALL, fg="#6f5b00", bg="#fff7d6",
                 justify="left", padx=10, pady=8).pack(anchor="w")

        return frame

    def _format_size(self, num_bytes):
        units = ["B", "KB", "MB", "GB", "TB"]
        size = float(num_bytes)
        for unit in units:
            if size < 1024 or unit == units[-1]:
                if unit == "B":
                    return f"{int(size)} {unit}"
                return f"{size:.1f} {unit}"
            size /= 1024.0

    def _format_mtime(self, timestamp):
        import datetime
        return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

    def _refresh_crypto_footer(self):
        label = SECURITY_LABELS.get(self._security_profile, "Custom")
        self._crypto_line.set(
            f"AES-256-GCM  ·  PBKDF2-SHA256  ·  {label} ({self._kdf_iterations//1000}k iterations)"
        )

    def _build_settings_panel(self):
        frame = tk.Frame(self, bg=BG, padx=24, pady=20)

        tk.Label(frame, text="SETTINGS", font=FONT_LABEL,
                 fg=SUBTEXT, bg=BG, anchor="w").pack(fill="x")

        card = tk.Frame(frame, bg=SURFACE, highlightthickness=1, highlightbackground=BORDER,
                        padx=14, pady=14)
        card.pack(fill="x", pady=(6, 12))

        tk.Label(card, text="AUTO-LOCK TIMEOUT", font=FONT_SMALL,
                 fg=SUBTEXT, bg=SURFACE, anchor="w").pack(fill="x")

        row = tk.Frame(card, bg=SURFACE)
        row.pack(fill="x", pady=(8, 6))

        self._idle_minutes_var = tk.StringVar(value=str(self._inactivity_lock_seconds // 60))
        tk.Spinbox(
            row,
            from_=1,
            to=240,
            textvariable=self._idle_minutes_var,
            font=FONT_MONO,
            bg="#f8fafc",
            fg=TEXT,
            insertbackground=ACCENT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=ACCENT,
            width=8,
        ).pack(side="left", ipady=6, padx=(0, 8))

        tk.Label(row, text="minutes", font=FONT_LABEL,
                 fg=TEXT, bg=SURFACE).pack(side="left")

        tk.Label(card, text="SECURITY LEVEL", font=FONT_SMALL,
                 fg=SUBTEXT, bg=SURFACE, anchor="w").pack(fill="x", pady=(10, 0))
        row_sec = tk.Frame(card, bg=SURFACE)
        row_sec.pack(fill="x", pady=(8, 6))

        self._sec_profile_var = tk.StringVar(value=self._security_profile)
        sec_menu = ttk.Combobox(
            row_sec,
            textvariable=self._sec_profile_var,
            state="readonly",
            values=list(SECURITY_PROFILES.keys()),
            width=12,
            font=FONT_MONO,
        )
        sec_menu.pack(side="left", padx=(0, 8))

        self._btn(card, "SAVE SETTINGS", self._apply_settings, accent=True).pack(anchor="w", pady=(6, 0))

        return frame

    def _apply_settings(self):
        raw = self._idle_minutes_var.get().strip()
        try:
            minutes = int(raw)
        except ValueError:
            self._alert_error("Invalid value", "Auto-lock timeout must be a whole number.")
            return

        if minutes < 1 or minutes > 240:
            self._alert_error("Invalid value", "Auto-lock timeout must be between 1 and 240 minutes.")
            return

        profile = self._sec_profile_var.get().strip().lower()
        if profile not in SECURITY_PROFILES:
            self._alert_error("Invalid value", "Security profile must be fast, balanced, or high.")
            return

        self._inactivity_lock_seconds = minutes * 60
        self._security_profile = profile
        self._kdf_iterations = SECURITY_PROFILES[profile]
        self._save_settings()
        self._refresh_crypto_footer()
        self._touch_activity()
        self._set_status(
            f"Settings saved. Auto-lock: {minutes} min, Security: {SECURITY_LABELS[profile]}.",
            SUCCESS,
        )

    def _build_lock_panel(self):
        frame = tk.Frame(self, bg=BG, padx=24, pady=20)

        # Folder path
        tk.Label(frame, text="FOLDER TO LOCK", font=FONT_LABEL,
                 fg=SUBTEXT, bg=BG, anchor="w").pack(fill="x")
        row1 = tk.Frame(frame, bg=BG)
        row1.pack(fill="x", pady=(4, 12))
        self._lock_path = tk.StringVar()
        tk.Entry(row1, textvariable=self._lock_path, font=FONT_MONO,
                 bg=SURFACE, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", bd=0, highlightthickness=1,
                 highlightbackground=BORDER, highlightcolor=ACCENT,
                 width=44).pack(side="left", ipady=7, padx=(0, 8))
        self._btn(row1, "BROWSE", self._browse_lock_folder).pack(side="left")

        # Password
        tk.Label(frame, text="PASSWORD", font=FONT_LABEL,
                 fg=SUBTEXT, bg=BG, anchor="w").pack(fill="x")
        row2 = tk.Frame(frame, bg=BG)
        row2.pack(fill="x", pady=(4, 12))
        self._lock_pw = tk.StringVar()
        self._lock_pw_entry = tk.Entry(row2, textvariable=self._lock_pw,
                 show="•", font=FONT_MONO,
                 bg=SURFACE, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", bd=0, highlightthickness=1,
                 highlightbackground=BORDER, highlightcolor=ACCENT,
                 width=44)
        self._lock_pw_entry.pack(side="left", ipady=7, padx=(0, 8))
        self._btn(row2, "SHOW", lambda: self._toggle_pw(self._lock_pw_entry, "lock")).pack(side="left")

        # Confirm password
        tk.Label(frame, text="CONFIRM PASSWORD", font=FONT_LABEL,
                 fg=SUBTEXT, bg=BG, anchor="w").pack(fill="x")
        row3 = tk.Frame(frame, bg=BG)
        row3.pack(fill="x", pady=(4, 16))
        self._lock_pw2 = tk.StringVar()
        self._lock_pw2_entry = tk.Entry(row3, textvariable=self._lock_pw2,
                 show="•", font=FONT_MONO,
                 bg=SURFACE, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", bd=0, highlightthickness=1,
                 highlightbackground=BORDER, highlightcolor=ACCENT,
                 width=44)
        self._lock_pw2_entry.pack(side="left", ipady=7, padx=(0, 8))
        self._btn(row3, "SHOW", lambda: self._toggle_pw(self._lock_pw2_entry, "lock2")).pack(side="left")

        # Warning note
        note = tk.Frame(frame, bg="#fff7d6", highlightthickness=1,
                highlightbackground="#e8d594")
        note.pack(fill="x", pady=(0, 16))
        tk.Label(note, text="⚠  The original folder is NOT deleted automatically.\n"
                             "   Delete it manually after confirming the .locked file.",
             font=FONT_SMALL, fg="#6f5b00", bg="#fff7d6",
                 justify="left", padx=10, pady=8).pack(anchor="w")

        # Lock button
        self._btn(frame, "ENCRYPT & LOCK  →", self._do_lock,
                  accent=True, full=True).pack(fill="x")

        return frame

    def _build_unlock_panel(self):
        frame = tk.Frame(self, bg=BG, padx=24, pady=20)

        # .locked file
        tk.Label(frame, text=".LOCKED FILE", font=FONT_LABEL,
                 fg=SUBTEXT, bg=BG, anchor="w").pack(fill="x")
        row1 = tk.Frame(frame, bg=BG)
        row1.pack(fill="x", pady=(4, 12))
        self._unlock_path = tk.StringVar()
        tk.Entry(row1, textvariable=self._unlock_path, font=FONT_MONO,
                 bg=SURFACE, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", bd=0, highlightthickness=1,
                 highlightbackground=BORDER, highlightcolor=ACCENT,
                 width=44).pack(side="left", ipady=7, padx=(0, 8))
        self._btn(row1, "BROWSE", self._browse_locked_file).pack(side="left")

        # Output directory
        tk.Label(frame, text="RESTORE TO FOLDER", font=FONT_LABEL,
                 fg=SUBTEXT, bg=BG, anchor="w").pack(fill="x")
        row2 = tk.Frame(frame, bg=BG)
        row2.pack(fill="x", pady=(4, 12))
        self._unlock_out = tk.StringVar()
        tk.Entry(row2, textvariable=self._unlock_out, font=FONT_MONO,
                 bg=SURFACE, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", bd=0, highlightthickness=1,
                 highlightbackground=BORDER, highlightcolor=ACCENT,
                 width=44).pack(side="left", ipady=7, padx=(0, 8))
        self._btn(row2, "BROWSE", self._browse_out_dir).pack(side="left")

        # Password
        tk.Label(frame, text="PASSWORD", font=FONT_LABEL,
                 fg=SUBTEXT, bg=BG, anchor="w").pack(fill="x")
        row3 = tk.Frame(frame, bg=BG)
        row3.pack(fill="x", pady=(4, 24))
        self._unlock_pw = tk.StringVar()
        self._unlock_pw_entry = tk.Entry(row3, textvariable=self._unlock_pw,
                 show="•", font=FONT_MONO,
                 bg=SURFACE, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", bd=0, highlightthickness=1,
                 highlightbackground=BORDER, highlightcolor=ACCENT,
                 width=44)
        self._unlock_pw_entry.pack(side="left", ipady=7, padx=(0, 8))
        self._btn(row3, "SHOW", lambda: self._toggle_pw(self._unlock_pw_entry, "unlock")).pack(side="left")

        # Unlock button
        self._btn(frame, "DECRYPT & RESTORE  →", self._do_unlock,
                  accent=True, full=True).pack(fill="x")

        return frame

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _btn(self, parent, text, cmd, accent=False, full=False):
        fg = "#ffffff" if accent else TEXT
        bg = ACCENT if accent else SURFACE
        abg = "#245f27" if accent else "#eef2f8"
        b = tk.Button(parent, text=text, command=cmd,
                      font=FONT_BTN, fg=fg, bg=bg,
                      activeforeground=fg, activebackground=abg,
                      relief="flat", bd=0, cursor="hand2",
                      padx=12, pady=6)
        if full:
            b.configure(pady=10)
        return b

    def _switch_tab(self):
        self._vault_frame.pack_forget()
        self._settings_frame.pack_forget()
        self._lock_frame.pack_forget()
        self._unlock_frame.pack_forget()

        prog_ready = hasattr(self, "_prog")

        if self._tab.get() == "vault":
            self._vault_frame.pack(fill="both", expand=True)
            if prog_ready and self._prog.winfo_manager() == "":
                self._prog.pack(pady=(6, 0))
        elif self._tab.get() == "settings":
            self._settings_frame.pack(fill="both", expand=True)
            if prog_ready:
                self._prog.pack_forget()
        elif self._tab.get() == "lock":
            self._lock_frame.pack(fill="x")
            if prog_ready and self._prog.winfo_manager() == "":
                self._prog.pack(pady=(6, 0))
        else:
            self._unlock_frame.pack(fill="x")
            if prog_ready and self._prog.winfo_manager() == "":
                self._prog.pack(pady=(6, 0))

    _pw_visible = {}

    def _toggle_pw(self, entry, key):
        visible = self._pw_visible.get(key, False)
        entry.config(show="" if not visible else "•")
        self._pw_visible[key] = not visible

    def _browse_lock_folder(self):
        d = filedialog.askdirectory(title="Select folder to lock")
        if d:
            self._lock_path.set(d)

    def _browse_locked_file(self):
        f = filedialog.askopenfilename(
            title="Select .locked file",
            filetypes=[("vault32 files", "*.locked"), ("All files", "*.*")]
        )
        if f:
            self._unlock_path.set(f)

    def _browse_out_dir(self):
        d = filedialog.askdirectory(title="Select restore destination")
        if d:
            self._unlock_out.set(d)

    def _set_status(self, msg, color=SUBTEXT):
        self._status.set(msg)
        self._status_lbl.config(fg=color)
        self.update_idletasks()

    def _set_progress(self, val):
        self._prog["value"] = val
        if hasattr(self, "_task_pct"):
            self._task_pct.set(f"{int(val)}%")
        self.update_idletasks()

    def _set_status_safe(self, msg, color=SUBTEXT):
        self.after(0, lambda m=msg, c=color: self._set_status(m, c))

    def _set_progress_safe(self, val):
        self.after(0, lambda v=val: self._set_progress(v))

    def _set_task_message(self, msg):
        if hasattr(self, "_task_msg"):
            self._task_msg.set(msg)

    def _set_task_message_safe(self, msg):
        self.after(0, lambda m=msg: self._set_task_message(m))

    def _update_vault_action_states(self):
        if not hasattr(self, "_btn_unlock_vault") or not hasattr(self, "_btn_lock_vault"):
            return
        if self._vault_unlocked:
            self._btn_unlock_vault.config(state=tk.DISABLED)
            self._btn_lock_vault.config(state=tk.NORMAL)
        else:
            self._btn_unlock_vault.config(state=tk.NORMAL)
            self._btn_lock_vault.config(state=tk.DISABLED)

    def _get_kdf_iteration_candidates(self):
        values = [self._kdf_iterations] + list(SECURITY_PROFILES.values())
        # Preserve order while deduplicating.
        return list(dict.fromkeys(values))

    def _set_vault_state(self, text, color=SUBTEXT):
        self._vault_state.set(text)
        self._vault_state_lbl.config(fg=color)

    def _place_dialog_center(self, dlg):
        self.update_idletasks()
        dlg.update_idletasks()

        w = dlg.winfo_reqwidth()
        h = dlg.winfo_reqheight()

        parent_w = self.winfo_width()
        parent_h = self.winfo_height()
        parent_x = self.winfo_rootx()
        parent_y = self.winfo_rooty()

        vroot_x = self.winfo_vrootx()
        vroot_y = self.winfo_vrooty()
        vroot_w = self.winfo_vrootwidth()
        vroot_h = self.winfo_vrootheight()

        # During early startup, parent geometry can be 1x1 at (0, 0); fallback to screen center.
        if parent_w <= 1 or parent_h <= 1 or not self.winfo_viewable():
            x = vroot_x + (vroot_w - w) // 2
            y = vroot_y + (vroot_h - h) // 2
        else:
            x = parent_x + (parent_w - w) // 2
            y = parent_y + (parent_h - h) // 2

        x = min(max(x, vroot_x), vroot_x + max(0, vroot_w - w))
        y = min(max(y, vroot_y), vroot_y + max(0, vroot_h - h))

        dlg.geometry(f"{w}x{h}+{x}+{y}")

    def _show_alert(self, title, message, kind="info", buttons=("OK",)):
        if threading.current_thread() is not threading.main_thread():
            result = {"value": buttons[0]}
            done = threading.Event()

            def _open_on_main():
                result["value"] = self._show_alert(title, message, kind=kind, buttons=buttons)
                done.set()

            self.after(0, _open_on_main)
            done.wait()
            return result["value"]

        palette = {
            "info": ("i", "#1565c0", "#e8f1fd"),
            "warning": ("!", "#b26a00", "#fff4e0"),
            "error": ("x", "#b71c1c", "#fdecec"),
        }
        icon_text, icon_fg, icon_bg = palette.get(kind, palette["info"])

        dlg = tk.Toplevel(self)
        dlg.withdraw()
        dlg.title(title)
        dlg.configure(bg=SURFACE)
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()

        shell = tk.Frame(dlg, bg=SURFACE, highlightthickness=1, highlightbackground=BORDER)
        shell.pack(fill="both", expand=True)

        top = tk.Frame(shell, bg=SURFACE, padx=16, pady=14)
        top.pack(fill="x")

        icon = tk.Label(top, text=icon_text, fg=icon_fg, bg=icon_bg,
                        font=("Segoe UI", 12, "bold"), width=2)
        icon.pack(side="left", padx=(0, 10))

        tk.Label(top, text=title, font=("Segoe UI", 12, "bold"),
                 fg=TEXT, bg=SURFACE, anchor="w").pack(side="left", fill="x", expand=True)

        tk.Frame(shell, bg=BORDER, height=1).pack(fill="x")

        tk.Label(shell, text=message, font=FONT_LABEL, fg=TEXT, bg=SURFACE,
                 justify="left", anchor="w", wraplength=430,
                 padx=16, pady=14).pack(fill="x")

        btn_row = tk.Frame(shell, bg=SURFACE, padx=16, pady=0)
        btn_row.pack(fill="x", pady=(0, 14))

        choice = {"value": buttons[0]}

        def choose(value):
            choice["value"] = value
            dlg.destroy()

        for i, label in enumerate(reversed(buttons)):
            primary = (i == len(buttons) - 1)
            fg = "#ffffff" if primary else TEXT
            bg = ACCENT if primary else "#eef2f8"
            active_bg = "#245f27" if primary else "#e2e8f0"
            tk.Button(
                btn_row,
                text=label,
                command=lambda v=label: choose(v),
                font=FONT_BTN,
                fg=fg,
                bg=bg,
                activeforeground=fg,
                activebackground=active_bg,
                relief="flat",
                bd=0,
                padx=14,
                pady=6,
                cursor="hand2",
            ).pack(side="right", padx=(8, 0))

        if "Cancel" in buttons:
            dlg.bind("<Escape>", lambda _e: choose("Cancel"))
        else:
            dlg.bind("<Escape>", lambda _e: choose(buttons[0]))

        self._place_dialog_center(dlg)
        dlg.deiconify()
        dlg.lift()
        dlg.focus_force()
        dlg.after_idle(lambda: self._place_dialog_center(dlg))

        dlg.wait_window()
        return choice["value"]

    def _alert_info(self, title, message):
        self._show_alert(title, message, kind="info", buttons=("OK",))

    def _alert_error(self, title, message):
        self._show_alert(title, message, kind="error", buttons=("OK",))

    def _alert_warning(self, title, message):
        self._show_alert(title, message, kind="warning", buttons=("OK",))

    def _alert_retry_cancel(self, title, message):
        return self._show_alert(title, message, kind="error", buttons=("Cancel", "Retry")) == "Retry"

    def _prompt_password_modal(self, title, prompt):
        dlg = tk.Toplevel(self)
        dlg.withdraw()
        dlg.title(title)
        dlg.configure(bg=SURFACE)
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()

        shell = tk.Frame(dlg, bg=SURFACE, highlightthickness=1, highlightbackground=BORDER)
        shell.pack(fill="both", expand=True)

        top = tk.Frame(shell, bg=SURFACE, padx=16, pady=14)
        top.pack(fill="x")
        tk.Label(top, text="*", fg="#1565c0", bg="#e8f1fd",
                 font=("Segoe UI", 12, "bold"), width=2).pack(side="left", padx=(0, 10))
        tk.Label(top, text=title, font=("Segoe UI", 12, "bold"),
                 fg=TEXT, bg=SURFACE, anchor="w").pack(side="left", fill="x", expand=True)

        tk.Frame(shell, bg=BORDER, height=1).pack(fill="x")

        body = tk.Frame(shell, bg=SURFACE, padx=16, pady=14)
        body.pack(fill="x")

        tk.Label(body, text=prompt, font=FONT_LABEL, fg=TEXT, bg=SURFACE,
                 justify="left", anchor="w", wraplength=430).pack(fill="x")

        pw_var = tk.StringVar()
        entry_wrap = tk.Frame(body, bg=SURFACE)
        entry_wrap.pack(fill="x", pady=(10, 0))
        entry = tk.Entry(entry_wrap, textvariable=pw_var, show="•", font=FONT_MONO,
                         bg="#f8fafc", fg=TEXT, insertbackground=ACCENT,
                         relief="flat", bd=0, highlightthickness=1,
                         highlightbackground=BORDER, highlightcolor=ACCENT)
        entry.pack(side="left", fill="x", expand=True, ipady=7, padx=(0, 8))

        visible = {"value": False}

        def toggle_show():
            visible["value"] = not visible["value"]
            entry.config(show="" if visible["value"] else "•")
            show_btn.config(text="HIDE" if visible["value"] else "SHOW")

        show_btn = tk.Button(
            entry_wrap,
            text="SHOW",
            command=toggle_show,
            font=FONT_BTN,
            fg=TEXT,
            bg="#eef2f8",
            activeforeground=TEXT,
            activebackground="#e2e8f0",
            relief="flat",
            bd=0,
            padx=12,
            pady=6,
            cursor="hand2",
        )
        show_btn.pack(side="left")

        btn_row = tk.Frame(shell, bg=SURFACE, padx=16, pady=0)
        btn_row.pack(fill="x", pady=(0, 14))

        result = {"value": None}

        def choose_ok():
            result["value"] = pw_var.get()
            dlg.destroy()

        def choose_cancel():
            result["value"] = None
            dlg.destroy()

        tk.Button(
            btn_row,
            text="Cancel",
            command=choose_cancel,
            font=FONT_BTN,
            fg=TEXT,
            bg="#eef2f8",
            activeforeground=TEXT,
            activebackground="#e2e8f0",
            relief="flat",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
        ).pack(side="right")

        tk.Button(
            btn_row,
            text="Continue",
            command=choose_ok,
            font=FONT_BTN,
            fg="#ffffff",
            bg=ACCENT,
            activeforeground="#ffffff",
            activebackground="#245f27",
            relief="flat",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
        ).pack(side="right", padx=(0, 8))

        dlg.bind("<Escape>", lambda _e: choose_cancel())
        dlg.bind("<Return>", lambda _e: choose_ok())

        self._place_dialog_center(dlg)
        dlg.deiconify()
        dlg.lift()
        dlg.focus_force()
        dlg.after_idle(lambda: self._place_dialog_center(dlg))

        entry.focus_set()
        dlg.wait_window()
        return result["value"]

    def _prompt_text_modal(self, title, prompt, initial_value=""):
        dlg = tk.Toplevel(self)
        dlg.withdraw()
        dlg.title(title)
        dlg.configure(bg=SURFACE)
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()

        shell = tk.Frame(dlg, bg=SURFACE, highlightthickness=1, highlightbackground=BORDER)
        shell.pack(fill="both", expand=True)

        top = tk.Frame(shell, bg=SURFACE, padx=16, pady=14)
        top.pack(fill="x")
        tk.Label(top, text="T", fg="#1565c0", bg="#e8f1fd",
                 font=("Segoe UI", 12, "bold"), width=2).pack(side="left", padx=(0, 10))
        tk.Label(top, text=title, font=("Segoe UI", 12, "bold"),
                 fg=TEXT, bg=SURFACE, anchor="w").pack(side="left", fill="x", expand=True)

        tk.Frame(shell, bg=BORDER, height=1).pack(fill="x")

        body = tk.Frame(shell, bg=SURFACE, padx=16, pady=14)
        body.pack(fill="x")

        tk.Label(body, text=prompt, font=FONT_LABEL, fg=TEXT, bg=SURFACE,
                 justify="left", anchor="w", wraplength=430).pack(fill="x")

        name_var = tk.StringVar(value=initial_value)
        entry = tk.Entry(body, textvariable=name_var, font=FONT_MONO,
                         bg="#f8fafc", fg=TEXT, insertbackground=ACCENT,
                         relief="flat", bd=0, highlightthickness=1,
                         highlightbackground=BORDER, highlightcolor=ACCENT)
        entry.pack(fill="x", ipady=7, pady=(10, 0))

        btn_row = tk.Frame(shell, bg=SURFACE, padx=16, pady=0)
        btn_row.pack(fill="x", pady=(0, 14))

        result = {"value": None}

        def choose_ok():
            result["value"] = name_var.get()
            dlg.destroy()

        def choose_cancel():
            result["value"] = None
            dlg.destroy()

        tk.Button(
            btn_row,
            text="Cancel",
            command=choose_cancel,
            font=FONT_BTN,
            fg=TEXT,
            bg="#eef2f8",
            activeforeground=TEXT,
            activebackground="#e2e8f0",
            relief="flat",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
        ).pack(side="right")

        tk.Button(
            btn_row,
            text="Rename",
            command=choose_ok,
            font=FONT_BTN,
            fg="#ffffff",
            bg=ACCENT,
            activeforeground="#ffffff",
            activebackground="#245f27",
            relief="flat",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
        ).pack(side="right", padx=(0, 8))

        dlg.bind("<Escape>", lambda _e: choose_cancel())
        dlg.bind("<Return>", lambda _e: choose_ok())

        self._place_dialog_center(dlg)
        dlg.deiconify()
        dlg.lift()
        dlg.focus_force()
        dlg.after_idle(lambda: self._place_dialog_center(dlg))

        entry.focus_set()
        entry.selection_range(0, tk.END)
        dlg.wait_window()
        return result["value"]

    # ── Default private vault flow ──────────────────────────────────────────

    def _prompt_new_password(self):
        while True:
            pw1 = self._prompt_password_modal(
                "Set Vault Password",
                "Create a password for your private vault:",
            )
            if pw1 is None:
                return None
            if not pw1:
                self._alert_error("Missing password", "Password cannot be empty.")
                continue

            pw2 = self._prompt_password_modal(
                "Confirm Password",
                "Re-enter password:",
            )
            if pw2 is None:
                return None
            if pw1 != pw2:
                self._alert_error("Password mismatch", "Passwords do not match.")
                continue
            return pw1

    def _startup_vault_flow(self):
        ok = self._unlock_private_vault_interactive(startup=True)
        if not ok:
            self.destroy()

    def _startup_unlock_tool_flow(self):
        self._tab.set("unlock")
        self._switch_tab()
        self._unlock_path.set(self._startup_locked_path)
        self._unlock_out.set(os.path.dirname(self._startup_locked_path))
        self._set_status("Opened .locked file from Explorer. Enter password to decrypt.", SUCCESS)

    def _unlock_private_vault_interactive(self, startup=False):
        os.makedirs(os.path.dirname(self._vault_dir), exist_ok=True)

        # If both exist (e.g., unclean shutdown), trust the encrypted source of truth.
        if os.path.isfile(self._vault_locked) and os.path.isdir(self._vault_dir):
            shutil.rmtree(self._vault_dir, ignore_errors=True)

        if os.path.isfile(self._vault_locked):
            while True:
                pw = self._prompt_password_modal(
                    "Unlock Private Vault",
                    "Enter vault password:",
                )
                if pw is None:
                    return False
                try:
                    self._set_status("Unlocking private vault…")
                    self._set_progress(0)
                    unlock_file(
                        self._vault_locked,
                        pw,
                        os.path.dirname(self._vault_dir),
                        progress_cb=self._set_progress,
                        kdf_iterations_list=self._get_kdf_iteration_candidates(),
                    )
                    os.makedirs(self._vault_dir, exist_ok=True)
                    self._vault_password = pw
                    self._vault_unlocked = True
                    self._touch_activity()
                    self._update_vault_action_states()
                    self._set_task_message("Vault unlocked.")
                    self._set_vault_state("State: Unlocked", SUCCESS)
                    self._set_status("Private vault unlocked.", SUCCESS)
                    self._refresh_vault_list()
                    return True
                except Exception as e:
                    retry = self._alert_retry_cancel("Unlock failed", str(e))
                    if not retry:
                        return False

        if os.path.isdir(self._vault_dir):
            pw = self._prompt_new_password()
            if pw is None:
                return False
            self._vault_password = pw
            self._vault_unlocked = True
            self._touch_activity()
            self._update_vault_action_states()
            self._set_task_message("Vault unlocked.")
            self._set_vault_state("State: Unlocked (new password set)", SUCCESS)
            self._set_status("Private vault is open.", SUCCESS)
            self._refresh_vault_list()
            return True

        pw = self._prompt_new_password()
        if pw is None:
            return False
        os.makedirs(self._vault_dir, exist_ok=True)
        self._vault_password = pw
        self._vault_unlocked = True
        self._touch_activity()
        self._update_vault_action_states()
        self._set_task_message("Vault unlocked.")
        self._set_vault_state("State: Unlocked", SUCCESS)
        self._set_status("Private vault ready.", SUCCESS)
        self._refresh_vault_list()
        if startup:
            self._alert_info("Vault ready", f"Your private vault is at:\n{self._vault_dir}")
        return True

    def _lock_private_vault(self, silent=False):
        if not self._vault_unlocked:
            if not silent:
                self._alert_info("Vault", "Vault is already locked.")
            return True
        if not self._vault_password:
            if not silent:
                self._alert_error("Vault", "No active vault password in memory.")
            return False

        try:
            self._set_status("Locking private vault…")
            self._set_progress(0)
            lock_folder(
                self._vault_dir,
                self._vault_password,
                progress_cb=self._set_progress,
                kdf_iterations=self._kdf_iterations,
            )
            shutil.rmtree(self._vault_dir)
            self._vault_unlocked = False
            self._vault_password = None
            self._vault_list.delete(0, tk.END)
            self._vault_items = []
            self._update_vault_action_states()
            self._set_task_message("Vault locked.")
            self._set_vault_state("State: Locked", SUBTEXT)
            self._set_status("Private vault locked.", SUCCESS)
            if not silent:
                self._alert_info("Vault", "Private vault locked.")
            return True
        except Exception as e:
            self._set_status(f"Error: {e}", DANGER)
            if not silent:
                self._alert_error("Lock failed", str(e))
            return False

    def _manual_lock_vault(self):
        if not self._vault_unlocked:
            self._alert_info("Vault", "Vault is already locked.")
            return
        if not self._vault_password:
            self._alert_error("Vault", "No active vault password in memory.")
            return

        vault_password = self._vault_password
        vault_dir = self._vault_dir

        def run():
            try:
                self._set_status_safe("Locking private vault…")
                self._set_progress_safe(0)
                self._set_task_message_safe("Locking vault…")
                lock_folder(
                    vault_dir,
                    vault_password,
                    progress_cb=self._set_progress_safe,
                    kdf_iterations=self._kdf_iterations,
                )
                shutil.rmtree(vault_dir)

                def finish_ui():
                    self._vault_unlocked = False
                    self._vault_password = None
                    self._vault_list.delete(0, tk.END)
                    self._vault_items = []
                    self._update_vault_action_states()
                    self._set_task_message("Vault locked.")
                    self._set_vault_state("State: Locked", SUBTEXT)
                    self._set_status("Private vault locked.", SUCCESS)
                    self._alert_info("Vault", "Private vault locked.")

                self.after(0, finish_ui)
            except Exception as e:
                self._set_status_safe(f"Error: {e}", DANGER)
                self._alert_error("Lock failed", str(e))

        threading.Thread(target=run, daemon=True).start()

    def _manual_unlock_vault(self):
        if self._vault_unlocked:
            self._alert_info("Vault", "Vault is already unlocked.")
            return
        ok = self._unlock_private_vault_interactive(startup=False)
        if not ok:
            self._set_status("Vault remains locked.", SUBTEXT)

    def _refresh_vault_list(self):
        self._vault_list.delete(0, tk.END)
        self._vault_items = []
        self._clear_vault_details()

        if not self._vault_unlocked or not os.path.isdir(self._vault_dir):
            self._vault_list.insert(tk.END, "[LOCKED] Unlock vault to browse files.")
            return

        for root, dirs, files in os.walk(self._vault_dir):
            rel_root = os.path.relpath(root, self._vault_dir)
            rel_root = "" if rel_root == "." else rel_root

            for d in sorted(dirs):
                rel = os.path.join(rel_root, d) if rel_root else d
                abs_path = os.path.join(self._vault_dir, rel)
                mtime = os.path.getmtime(abs_path)
                self._vault_items.append({
                    "rel": rel,
                    "abs": abs_path,
                    "is_dir": True,
                    "size": 0,
                    "mtime": mtime,
                })
                self._vault_list.insert(tk.END, f"[DIR]  {rel}   |   {self._format_mtime(mtime)}")

            for f in sorted(files):
                rel = os.path.join(rel_root, f) if rel_root else f
                abs_path = os.path.join(self._vault_dir, rel)
                size = os.path.getsize(abs_path)
                mtime = os.path.getmtime(abs_path)
                self._vault_items.append({
                    "rel": rel,
                    "abs": abs_path,
                    "is_dir": False,
                    "size": size,
                    "mtime": mtime,
                })
                self._vault_list.insert(
                    tk.END,
                    f"[FILE] {rel}   |   {self._format_size(size)}   |   {self._format_mtime(mtime)}"
                )

        if not self._vault_items:
            self._vault_list.insert(tk.END, "(Vault is empty)")

    def _vault_unique_path(self, name):
        base, ext = os.path.splitext(name)
        candidate = os.path.join(self._vault_dir, name)
        i = 1
        while os.path.exists(candidate):
            candidate = os.path.join(self._vault_dir, f"{base}_{i}{ext}")
            i += 1
        return candidate

    def _copy_file_with_progress(self, src, dst, progress, progress_cb=None):
        chunk_size = 1024 * 1024
        with open(src, "rb") as rf, open(dst, "wb") as wf:
            while True:
                chunk = rf.read(chunk_size)
                if not chunk:
                    break
                wf.write(chunk)
                progress["copied"] += len(chunk)
                if progress["total"] > 0:
                    pct = int((progress["copied"] / progress["total"]) * 100)
                    if progress_cb:
                        progress_cb(min(100, max(0, pct)))
        shutil.copystat(src, dst)

    def _vault_add_files(self):
        if not self._vault_unlocked:
            self._alert_error("Vault locked", "Unlock vault first.")
            return

        files = filedialog.askopenfilenames(title="Select files to add")
        if not files:
            return

        valid_files = [src for src in files if os.path.isfile(src)]
        if not valid_files:
            self._alert_error("No files", "No valid files were selected.")
            return

        total_bytes = 0
        for src in valid_files:
            try:
                total_bytes += os.path.getsize(src)
            except OSError:
                continue

        def run():
            try:
                self._set_progress_safe(0)
                self._set_task_message_safe("Adding files…")
                added = 0
                progress = {"copied": 0, "total": total_bytes}
                file_count = len(valid_files)
                for i, src in enumerate(valid_files, start=1):
                    dst = self._vault_unique_path(os.path.basename(src))
                    self._set_status_safe(f"Adding file {i}/{file_count}: {os.path.basename(src)}")
                    self._set_task_message_safe(f"Adding {os.path.basename(src)} ({i}/{file_count})")
                    self._copy_file_with_progress(src, dst, progress, progress_cb=self._set_progress_safe)
                    added += 1

                self.after(0, self._refresh_vault_list)
                self._set_progress_safe(100)
                self._set_task_message_safe(f"Added {added} file(s).")
                self._set_status_safe(f"Added {added} file(s) to private vault.", SUCCESS)
            except Exception as e:
                self._set_status_safe(f"Error: {e}", DANGER)
                self._alert_error("Add files failed", str(e))

        threading.Thread(target=run, daemon=True).start()

    def _vault_add_folder(self):
        if not self._vault_unlocked:
            self._alert_error("Vault locked", "Unlock vault first.")
            return

        src = filedialog.askdirectory(title="Select folder to copy into vault")
        if not src:
            return
        if os.path.normpath(src) == os.path.normpath(self._vault_dir):
            self._alert_error("Invalid folder", "Cannot copy vault into itself.")
            return

        dst = self._vault_unique_path(os.path.basename(os.path.normpath(src)))
        shutil.copytree(src, dst)
        self._refresh_vault_list()
        self._set_status("Folder added to private vault.", SUCCESS)

    def _get_selected_vault_targets(self):
        if not self._vault_unlocked:
            self._alert_error("Vault locked", "Unlock vault first.")
            return []

        sel = self._vault_list.curselection()
        if not sel:
            self._alert_info("Selection required", "Select one or more entries first.")
            return []

        targets = []
        vault_root = os.path.normpath(self._vault_dir)
        for idx in sel:
            if idx >= len(self._vault_items):
                continue
            item = self._vault_items[idx]
            target = os.path.normpath(item["abs"])
            if os.path.commonpath([target, vault_root]) != vault_root:
                continue
            targets.append(target)

        return targets

    def _get_single_selected_vault_item(self):
        if not self._vault_unlocked:
            self._alert_error("Vault locked", "Unlock vault first.")
            return None

        sel = self._vault_list.curselection()
        if len(sel) != 1:
            self._alert_info("Selection required", "Select exactly one item.")
            return None

        idx = sel[0]
        if idx >= len(self._vault_items):
            self._alert_error("Selection error", "Invalid selection.")
            return None

        return self._vault_items[idx]

    def _clear_vault_details(self):
        self._details_name.set("Name: -")
        self._details_type.set("Type: -")
        self._details_size.set("Size: -")
        self._details_mod.set("Modified: -")
        self._details_path.set("Path: -")

    def _on_vault_selection_changed(self, _event=None):
        sel = self._vault_list.curselection()
        if len(sel) != 1:
            self._clear_vault_details()
            if len(sel) > 1:
                self._details_name.set(f"Name: {len(sel)} items selected")
            return

        idx = sel[0]
        if idx >= len(self._vault_items):
            self._clear_vault_details()
            return

        item = self._vault_items[idx]
        item_name = os.path.basename(item["rel"]) if item["rel"] else item["rel"]
        item_type = "Folder" if item["is_dir"] else "File"
        item_size = "-" if item["is_dir"] else self._format_size(item["size"])

        self._details_name.set(f"Name: {item_name}")
        self._details_type.set(f"Type: {item_type}")
        self._details_size.set(f"Size: {item_size}")
        self._details_mod.set(f"Modified: {self._format_mtime(item['mtime'])}")
        self._details_path.set(f"Path: {item['abs']}")

    def _vault_open_selected(self, _event=None):
        targets = self._get_selected_vault_targets()
        if not targets:
            return

        opened = 0
        for target in targets:
            if not os.path.exists(target):
                continue
            try:
                os.startfile(target)
                opened += 1
            except Exception as e:
                self._alert_error("Open failed", str(e))
                return

        self._set_status(f"Opened {opened} item(s).", SUCCESS)

    def _vault_rename_selected(self):
        item = self._get_single_selected_vault_item()
        if not item:
            return

        old_path = item["abs"]
        old_name = os.path.basename(old_path)
        new_name = self._prompt_text_modal(
            "Rename Item",
            "Enter a new name for the selected item:",
            initial_value=old_name,
        )
        if new_name is None:
            return

        new_name = new_name.strip()
        if not new_name:
            self._alert_error("Invalid name", "Name cannot be empty.")
            return

        invalid_chars = '<>:"/\\|?*'
        if any(ch in new_name for ch in invalid_chars):
            self._alert_error("Invalid name", "Name contains invalid characters.")
            return

        parent_dir = os.path.dirname(old_path)
        new_path = os.path.normpath(os.path.join(parent_dir, new_name))
        vault_root = os.path.normpath(self._vault_dir)
        if os.path.commonpath([new_path, vault_root]) != vault_root:
            self._alert_error("Invalid path", "The new name resolves outside the vault.")
            return
        if os.path.exists(new_path):
            self._alert_error("Name exists", "An item with that name already exists.")
            return

        try:
            os.rename(old_path, new_path)
        except Exception as e:
            self._alert_error("Rename failed", str(e))
            return

        self._refresh_vault_list()
        self._set_status(f"Renamed '{old_name}' to '{new_name}'.", SUCCESS)

    def _vault_remove_selected(self):
        targets = self._get_selected_vault_targets()
        if not targets:
            return

        removed = 0
        for target in targets:
            if not os.path.exists(target):
                continue

            if os.path.isdir(target):
                shutil.rmtree(target, ignore_errors=True)
                removed += 1
            elif os.path.isfile(target):
                os.remove(target)
                removed += 1

        self._refresh_vault_list()
        self._set_status(f"Removed {removed} item(s) from private vault.", SUCCESS)

    def _open_vault_folder(self):
        if not self._vault_unlocked:
            self._alert_error("Vault locked", "Unlock vault first.")
            return
        os.startfile(self._vault_dir)

    def _on_close(self):
        if self._vault_unlocked:
            if self._lock_private_vault(silent=True):
                self.destroy()
                return

            while True:
                choice = self._show_alert(
                    "Lock failed on exit",
                    "Vault could not be locked (a file may still be in use).\n\n"
                    "Choose Retry to try locking again, or Exit Anyway to close without locking.",
                    kind="warning",
                    buttons=("Cancel", "Exit Anyway", "Retry"),
                )

                if choice == "Retry":
                    if self._lock_private_vault(silent=True):
                        self.destroy()
                        return
                    continue

                if choice == "Exit Anyway":
                    self.destroy()
                return
        self.destroy()

    # ── Actions ───────────────────────────────────────────────────────────────

    def _do_lock(self):
        folder = self._lock_path.get().strip()
        pw = self._lock_pw.get()
        pw2 = self._lock_pw2.get()

        if not folder:
            self._alert_error("Missing input", "Please select a folder.")
            return
        if not pw:
            self._alert_error("Missing input", "Please enter a password.")
            return
        if pw != pw2:
            self._alert_error("Password mismatch", "Passwords do not match.")
            return

        def run():
            try:
                self._set_status_safe("Encrypting…")
                self._set_progress_safe(0)
                self._set_task_message_safe("Tool lock in progress…")
                out = lock_folder(
                    folder,
                    pw,
                    progress_cb=self._set_progress_safe,
                    kdf_iterations=self._kdf_iterations,
                )
                self._set_status_safe(f"Locked → {os.path.basename(out)}", SUCCESS)
                self._set_task_message_safe("Tool lock complete.")
                self._alert_info(
                    "Locked",
                    f"Encrypted successfully:\n{out}\n\n"
                    "Remember to manually delete the original folder."
                )
            except Exception as e:
                self._set_status_safe(f"Error: {e}", DANGER)
                self._alert_error("Error", str(e))

        threading.Thread(target=run, daemon=True).start()

    def _do_unlock(self):
        locked = self._unlock_path.get().strip()
        out_dir = self._unlock_out.get().strip()
        pw = self._unlock_pw.get()

        if not locked:
            self._alert_error("Missing input", "Please select a .locked file.")
            return
        if not out_dir:
            self._alert_error("Missing input", "Please select a restore destination.")
            return
        if not pw:
            self._alert_error("Missing input", "Please enter the password.")
            return

        def run():
            try:
                self._set_status_safe("Decrypting…")
                self._set_progress_safe(0)
                self._set_task_message_safe("Tool unlock in progress…")
                unlock_file(
                    locked,
                    pw,
                    out_dir,
                    progress_cb=self._set_progress_safe,
                    kdf_iterations_list=self._get_kdf_iteration_candidates(),
                )
                self._set_status_safe("Decrypted successfully.", SUCCESS)
                self._set_task_message_safe("Tool unlock complete.")
                self._alert_info("Unlocked", f"Files restored to:\n{out_dir}")
            except Exception as e:
                self._set_status_safe(f"Error: {e}", DANGER)
                self._alert_error("Error", str(e))

        threading.Thread(target=run, daemon=True).start()
