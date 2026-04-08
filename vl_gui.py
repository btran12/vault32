"""vault32 PySide6 GUI application."""

import json
import os
import shutil
import sys
import threading
import time
from datetime import datetime

from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Signal
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from vl_crypto import (
    INACTIVITY_LOCK_SECONDS,
    SECURITY_LABELS,
    SECURITY_PROFILES,
    lock_folder,
    unlock_file,
)


THEMES = {
    "forest": {
        "bg": "#F4FAF6",
        "surface": "#FFFFFF",
        "surface_variant": "#EDF4EF",
        "border": "#D4E1D8",
        "text": "#17211B",
        "muted": "#5B6B62",
        "accent": "#1F7A4F",
        "on_accent": "#FFFFFF",
        "accent_container": "#D6EFE1",
        "warning_bg": "#FFF4E4",
        "warning_border": "#EFD3AD",
        "warning_text": "#7B4B00",
    },
    "slate": {
        "bg": "#F5F7FB",
        "surface": "#FFFFFF",
        "surface_variant": "#EDF1F8",
        "border": "#D5DCE8",
        "text": "#182236",
        "muted": "#566178",
        "accent": "#345CA8",
        "on_accent": "#FFFFFF",
        "accent_container": "#DCE6FB",
        "warning_bg": "#FFF4E4",
        "warning_border": "#EFD3AD",
        "warning_text": "#7B4B00",
    },
    "midnight": {
        "bg": "#0F141D",
        "surface": "#161D29",
        "surface_variant": "#1B2433",
        "border": "#2B3A4F",
        "text": "#E7EDF7",
        "muted": "#A3B0C4",
        "accent": "#58A6FF",
        "on_accent": "#0B1220",
        "accent_container": "#223956",
        "warning_bg": "#3E2E11",
        "warning_border": "#6A4D18",
        "warning_text": "#FFD58F",
    },
}


class _ActivityFilter(QObject):
    def __init__(self, callback):
        super().__init__()
        self._callback = callback

    def eventFilter(self, _obj, event):
        if event.type() in (
            QEvent.KeyPress,
            QEvent.MouseButtonPress,
            QEvent.MouseMove,
            QEvent.Wheel,
        ):
            self._callback()
        return False


class VaultLockApp(QMainWindow):
    uiCall = Signal(object)
    statusSignal = Signal(str)
    taskSignal = Signal(str)
    progressSignal = Signal(int)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("vault32")
        self.setMinimumSize(860, 760)

        home = os.path.expanduser("~")
        default_vault_dir = os.path.join(home, "vault32Private")
        legacy_vault_dir = os.path.join(home, "VaultLockPrivate")
        default_config_path = os.path.join(home, ".vault32_settings.json")
        legacy_config_path = os.path.join(home, ".vaultlock_settings.json")

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
        self._theme_name = "forest"
        self._known_vault_dirs = []
        self._remember_vault_dir(self._vault_dir)

        self._load_settings()
        self._build_ui()
        self._apply_theme()
        self.uiCall.connect(lambda fn: fn())
        self.statusSignal.connect(self._set_status)
        self.taskSignal.connect(self._set_task)
        self.progressSignal.connect(self._set_progress)
        self._set_status("Ready.")
        self._refresh_vault_list()
        self._update_vault_action_states()

        self._activity_filter = _ActivityFilter(self._touch_activity)
        QApplication.instance().installEventFilter(self._activity_filter)

        self._inactivity_timer = QTimer(self)
        self._inactivity_timer.timeout.connect(self._check_inactivity_autolock)
        self._inactivity_timer.start(5000)

        startup_locked_path = self._get_startup_locked_path()
        if startup_locked_path:
            self._tabs.setCurrentWidget(self._unlock_tab)
            self._unlock_path_edit.setText(startup_locked_path)
            self._unlock_out_edit.setText(os.path.dirname(startup_locked_path))
            self._set_status("Opened .locked file from Explorer. Enter password to decrypt.")
        else:
            QTimer.singleShot(120, self._startup_vault_flow)

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        main = QVBoxLayout(root)
        main.setContentsMargins(18, 14, 18, 14)
        main.setSpacing(10)

        header = QFrame()
        hbox = QHBoxLayout(header)
        hbox.setContentsMargins(8, 8, 8, 8)
        title = QLabel("vault32")
        title.setObjectName("Title")
        subtitle = QLabel("PySide6 Desktop Vault")
        subtitle.setObjectName("Muted")
        hbox.addWidget(title)
        hbox.addSpacing(10)
        hbox.addWidget(subtitle)
        hbox.addStretch(1)
        main.addWidget(header)

        self._tabs = QTabWidget()
        self._vault_tab = QWidget()
        self._settings_tab = QWidget()
        self._lock_tab = QWidget()
        self._unlock_tab = QWidget()

        self._tabs.addTab(self._vault_tab, "Private Vault")
        self._tabs.addTab(self._settings_tab, "Settings")
        self._tabs.addTab(self._lock_tab, "Lock Folder")
        self._tabs.addTab(self._unlock_tab, "Unlock File")

        self._build_vault_tab()
        self._build_settings_tab()
        self._build_lock_tab()
        self._build_unlock_tab()

        main.addWidget(self._tabs, 1)

        status_card = QFrame()
        v = QVBoxLayout(status_card)
        v.setContentsMargins(12, 10, 12, 10)
        self._status_label = QLabel("Ready.")
        self._task_label = QLabel("No active task.")
        self._task_label.setObjectName("Muted")
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._crypto_footer = QLabel("")
        self._crypto_footer.setObjectName("Muted")
        self._refresh_crypto_footer()

        v.addWidget(self._status_label)
        v.addWidget(self._task_label)
        v.addWidget(self._progress)
        v.addWidget(self._crypto_footer)
        main.addWidget(status_card)

        self._apply_clickable_cursors()

    def _apply_clickable_cursors(self):
        for btn in self.findChildren(QPushButton):
            btn.setCursor(Qt.PointingHandCursor)

        self._tabs.tabBar().setCursor(Qt.PointingHandCursor)

        for combo in self.findChildren(QComboBox):
            combo.setCursor(Qt.PointingHandCursor)

        for spin in self.findChildren(QSpinBox):
            spin.setCursor(Qt.PointingHandCursor)

        self._vault_list.setCursor(Qt.PointingHandCursor)

    def _build_vault_tab(self):
        layout = QVBoxLayout(self._vault_tab)
        layout.setContentsMargins(6, 8, 6, 8)
        layout.setSpacing(10)

        path_card = self._card()
        path_layout = QHBoxLayout(path_card)
        path_layout.addWidget(QLabel("Private Vault"))
        self._vault_path_edit = QLineEdit(self._vault_dir)
        self._vault_path_edit.setReadOnly(True)
        path_layout.addWidget(self._vault_path_edit, 1)
        path_layout.addWidget(self._make_button("Open", self._open_vault_folder))
        layout.addWidget(path_card)

        state_card = self._card()
        s = QHBoxLayout(state_card)
        self._vault_state_label = QLabel("State: Locked")
        s.addWidget(self._vault_state_label)
        s.addStretch(1)
        self._btn_unlock_vault = self._make_button("Unlock", self._manual_unlock_vault)
        self._btn_lock_vault = self._make_button("Lock", self._manual_lock_vault, primary=True)
        s.addWidget(self._btn_unlock_vault)
        s.addWidget(self._btn_lock_vault)
        layout.addWidget(state_card)

        actions = self._card()
        a = QHBoxLayout(actions)
        for text, slot in [
            ("Add File", self._vault_add_files),
            ("Add Folder", self._vault_add_folder),
            ("Open", self._vault_open_selected),
            ("Rename", self._vault_rename_selected),
            ("Remove", self._vault_remove_selected),
            ("Refresh", self._refresh_vault_list),
        ]:
            a.addWidget(self._make_button(text, slot))
        layout.addWidget(actions)

        self._vault_list = QListWidget()
        self._vault_list.itemSelectionChanged.connect(self._on_vault_selection_changed)
        self._vault_list.itemDoubleClicked.connect(lambda _i: self._vault_open_selected())
        layout.addWidget(self._vault_list, 1)

        details = self._card()
        d = QGridLayout(details)
        self._details_name = QLabel("Name: -")
        self._details_type = QLabel("Type: -")
        self._details_size = QLabel("Size: -")
        self._details_mod = QLabel("Modified: -")
        self._details_path = QLabel("Path: -")
        self._details_path.setWordWrap(True)
        d.addWidget(self._details_name, 0, 0)
        d.addWidget(self._details_type, 1, 0)
        d.addWidget(self._details_size, 2, 0)
        d.addWidget(self._details_mod, 3, 0)
        d.addWidget(self._details_path, 4, 0)
        layout.addWidget(details)

    def _build_settings_tab(self):
        layout = QVBoxLayout(self._settings_tab)
        layout.setContentsMargins(6, 8, 6, 8)
        layout.setSpacing(10)

        card = self._card()
        g = QGridLayout(card)

        g.addWidget(QLabel("Auto-lock timeout (minutes)"), 0, 0)
        self._idle_minutes_spin = QSpinBox()
        self._idle_minutes_spin.setRange(1, 240)
        self._idle_minutes_spin.setValue(self._inactivity_lock_seconds // 60)
        g.addWidget(self._idle_minutes_spin, 0, 1)

        g.addWidget(QLabel("Security profile"), 1, 0)
        self._security_combo = QComboBox()
        for key in SECURITY_PROFILES:
            self._security_combo.addItem(key)
        self._security_combo.setCurrentText(self._security_profile)
        g.addWidget(self._security_combo, 1, 1)

        g.addWidget(QLabel("Theme"), 2, 0)
        self._theme_combo = QComboBox()
        for key in THEMES:
            self._theme_combo.addItem(key)
        self._theme_combo.setCurrentText(self._theme_name)
        g.addWidget(self._theme_combo, 2, 1)

        save_btn = self._make_button("Save Settings", self._apply_settings, primary=True)
        g.addWidget(save_btn, 3, 0, 1, 2)

        layout.addWidget(card)
        layout.addStretch(1)

    def _build_lock_tab(self):
        layout = QVBoxLayout(self._lock_tab)
        layout.setContentsMargins(6, 8, 6, 8)
        layout.setSpacing(10)

        card = self._card()
        g = QGridLayout(card)

        self._lock_path_edit = QLineEdit()
        self._lock_pw_edit = QLineEdit()
        self._lock_pw_edit.setEchoMode(QLineEdit.Password)
        self._lock_pw2_edit = QLineEdit()
        self._lock_pw2_edit.setEchoMode(QLineEdit.Password)

        g.addWidget(QLabel("Folder to lock"), 0, 0)
        g.addWidget(self._lock_path_edit, 0, 1)
        g.addWidget(self._make_button("Browse", self._browse_lock_folder), 0, 2)

        g.addWidget(QLabel("Password"), 1, 0)
        g.addWidget(self._lock_pw_edit, 1, 1)
        g.addWidget(self._make_button("Show", lambda: self._toggle_password(self._lock_pw_edit)), 1, 2)

        g.addWidget(QLabel("Confirm password"), 2, 0)
        g.addWidget(self._lock_pw2_edit, 2, 1)
        g.addWidget(self._make_button("Show", lambda: self._toggle_password(self._lock_pw2_edit)), 2, 2)

        warning = QLabel("The original folder is not deleted automatically. Delete it only after verifying .locked output.")
        warning.setObjectName("Warning")
        warning.setWordWrap(True)
        g.addWidget(warning, 3, 0, 1, 3)

        g.addWidget(self._make_button("Encrypt and Lock", self._do_lock, primary=True), 4, 0, 1, 3)

        layout.addWidget(card)
        layout.addStretch(1)

    def _build_unlock_tab(self):
        layout = QVBoxLayout(self._unlock_tab)
        layout.setContentsMargins(6, 8, 6, 8)
        layout.setSpacing(10)

        card = self._card()
        g = QGridLayout(card)

        self._unlock_path_edit = QLineEdit()
        self._unlock_out_edit = QLineEdit()
        self._unlock_pw_edit = QLineEdit()
        self._unlock_pw_edit.setEchoMode(QLineEdit.Password)

        g.addWidget(QLabel(".locked file"), 0, 0)
        g.addWidget(self._unlock_path_edit, 0, 1)
        g.addWidget(self._make_button("Browse", self._browse_locked_file), 0, 2)

        g.addWidget(QLabel("Restore to folder"), 1, 0)
        g.addWidget(self._unlock_out_edit, 1, 1)
        g.addWidget(self._make_button("Browse", self._browse_out_dir), 1, 2)

        g.addWidget(QLabel("Password"), 2, 0)
        g.addWidget(self._unlock_pw_edit, 2, 1)
        g.addWidget(self._make_button("Show", lambda: self._toggle_password(self._unlock_pw_edit)), 2, 2)

        g.addWidget(self._make_button("Decrypt and Restore", self._do_unlock, primary=True), 3, 0, 1, 3)

        layout.addWidget(card)
        layout.addStretch(1)

    def _card(self):
        card = QFrame()
        card.setObjectName("Card")
        return card

    def _make_button(self, text, slot, primary=False):
        btn = QPushButton(text)
        btn.clicked.connect(slot)
        if primary:
            btn.setObjectName("PrimaryButton")
        return btn

    def _toggle_password(self, edit):
        if edit.echoMode() == QLineEdit.Password:
            edit.setEchoMode(QLineEdit.Normal)
        else:
            edit.setEchoMode(QLineEdit.Password)

    def _apply_theme(self):
        t = THEMES.get(self._theme_name, THEMES["forest"])
        style = f"""
        QWidget {{
            background: {t['bg']};
            color: {t['text']};
            font-family: 'Segoe UI';
            font-size: 10pt;
        }}
        QFrame#Card {{
            background: {t['surface']};
            border: 1px solid {t['border']};
            border-radius: 10px;
            padding: 4px;
        }}
        QLabel#Title {{
            font-size: 24px;
            font-weight: 600;
            color: {t['accent']};
        }}
        QLabel#Muted {{
            color: {t['muted']};
        }}
        QLabel#Warning {{
            background: {t['warning_bg']};
            border: 1px solid {t['warning_border']};
            border-radius: 8px;
            color: {t['warning_text']};
            padding: 8px;
        }}
        QLineEdit, QListWidget, QComboBox, QSpinBox {{
            background: {t['surface_variant']};
            border: 1px solid {t['border']};
            border-radius: 8px;
            padding: 6px;
        }}
        QTabWidget::pane {{
            border: 1px solid {t['border']};
            border-radius: 10px;
            top: -1px;
            background: {t['surface']};
        }}
        QTabBar::tab {{
            background: {t['surface_variant']};
            border: 1px solid {t['border']};
            border-bottom: none;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            padding: 8px 14px;
            margin-right: 3px;
            color: {t['muted']};
        }}
        QTabBar::tab:selected {{
            background: {t['accent_container']};
            color: {t['text']};
        }}
        QPushButton {{
            background: {t['surface_variant']};
            border: 1px solid {t['border']};
            border-radius: 8px;
            padding: 7px 12px;
        }}
        QPushButton:hover {{
            background: {t['accent_container']};
        }}
        QPushButton#PrimaryButton {{
            background: {t['accent']};
            border: 1px solid {t['accent']};
            color: {t['on_accent']};
            font-weight: 600;
        }}
        QPushButton#PrimaryButton:hover {{
            background: {t['accent']};
            opacity: 0.9;
        }}
        QProgressBar {{
            border: 1px solid {t['border']};
            border-radius: 6px;
            text-align: center;
            background: {t['surface_variant']};
        }}
        QProgressBar::chunk {{
            background: {t['accent']};
            border-radius: 5px;
        }}
        """
        self.setStyleSheet(style)

    def _touch_activity(self):
        self._last_activity_ts = time.time()

    def _run_on_ui(self, fn):
        self.uiCall.emit(fn)

    def _set_status(self, text):
        self._status_label.setText(text)

    def _set_status_safe(self, text):
        self.statusSignal.emit(text)

    def _set_task(self, text):
        self._task_label.setText(text)

    def _set_task_safe(self, text):
        self.taskSignal.emit(text)

    def _set_progress(self, value):
        self._progress.setValue(max(0, min(100, int(value))))

    def _set_progress_safe(self, value):
        self.progressSignal.emit(int(value))

    def _refresh_crypto_footer(self):
        label = SECURITY_LABELS.get(self._security_profile, "Custom")
        self._crypto_footer.setText(
            f"AES-256-GCM • PBKDF2-SHA256 • {label} ({self._kdf_iterations // 1000}k iterations)"
        )

    def _normalize_vault_dir(self, vault_dir):
        return os.path.abspath(str(vault_dir).strip())

    def _remember_vault_dir(self, vault_dir, save=False):
        norm = self._normalize_vault_dir(vault_dir)
        if not norm:
            return
        self._known_vault_dirs = [p for p in self._known_vault_dirs if p != norm]
        self._known_vault_dirs.insert(0, norm)
        self._known_vault_dirs = self._known_vault_dirs[:30]
        if save:
            self._save_settings()

    def _load_settings(self):
        if not os.path.isfile(self._config_path):
            return
        try:
            with open(self._config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            minutes = int(data.get("auto_lock_minutes", INACTIVITY_LOCK_SECONDS // 60))
            self._inactivity_lock_seconds = max(1, min(240, minutes)) * 60
            profile = str(data.get("security_profile", self._security_profile)).lower()
            if profile in SECURITY_PROFILES:
                self._security_profile = profile
                self._kdf_iterations = SECURITY_PROFILES[profile]
            theme = str(data.get("theme", self._theme_name)).lower()
            if theme in THEMES:
                self._theme_name = theme
            vault_dir = str(data.get("vault_dir", "")).strip()
            if vault_dir:
                self._vault_dir = self._normalize_vault_dir(vault_dir)
            known_vault_dirs = data.get("known_vault_dirs", [])
            if isinstance(known_vault_dirs, list):
                for path in known_vault_dirs:
                    if isinstance(path, str) and path.strip():
                        self._remember_vault_dir(path)
            self._remember_vault_dir(self._vault_dir)
            self._vault_locked = self._vault_dir + ".locked"
        except Exception:
            pass

    def _save_settings(self):
        data = {
            "auto_lock_minutes": self._inactivity_lock_seconds // 60,
            "security_profile": self._security_profile,
            "theme": self._theme_name,
            "vault_dir": self._vault_dir,
            "known_vault_dirs": self._known_vault_dirs,
        }
        with open(self._config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _apply_settings(self):
        minutes = self._idle_minutes_spin.value()
        profile = self._security_combo.currentText().strip().lower()
        theme = self._theme_combo.currentText().strip().lower()

        if profile not in SECURITY_PROFILES:
            self._alert_error("Invalid value", "Security profile must be fast, balanced, or high.")
            return
        if theme not in THEMES:
            self._alert_error("Invalid value", "Theme must be forest, slate, or midnight.")
            return

        self._inactivity_lock_seconds = minutes * 60
        self._security_profile = profile
        self._kdf_iterations = SECURITY_PROFILES[profile]
        self._theme_name = theme
        self._save_settings()
        self._refresh_crypto_footer()
        self._apply_theme()
        self._set_status(
            f"Settings saved. Auto-lock: {minutes} min, Security: {SECURITY_LABELS[profile]}, Theme: {theme}."
        )

    def _alert_info(self, title, message):
        QMessageBox.information(self, title, message)

    def _alert_error(self, title, message):
        QMessageBox.critical(self, title, message)

    def _alert_warning(self, title, message):
        QMessageBox.warning(self, title, message)

    def _prompt_password(self, title, prompt):
        text, ok = QInputDialog.getText(self, title, prompt, QLineEdit.Password)
        if not ok:
            return None
        return text

    def _prompt_text(self, title, prompt, initial=""):
        text, ok = QInputDialog.getText(self, title, prompt, QLineEdit.Normal, initial)
        if not ok:
            return None
        return text

    def _get_startup_locked_path(self):
        for arg in sys.argv[1:]:
            candidate = os.path.abspath(arg)
            if os.path.isfile(candidate) and candidate.lower().endswith(".locked"):
                return candidate
        return None

    def _set_active_vault_dir(self, vault_dir):
        self._vault_dir = self._normalize_vault_dir(vault_dir)
        self._vault_locked = self._vault_dir + ".locked"
        self._remember_vault_dir(self._vault_dir, save=True)
        if hasattr(self, "_vault_path_edit"):
            self._vault_path_edit.setText(self._vault_dir)

    def _select_known_vault_dir(self):
        if not self._known_vault_dirs:
            return None

        options = list(self._known_vault_dirs) + ["<Browse for another vault...>"]
        current = 0
        if self._vault_dir in self._known_vault_dirs:
            current = self._known_vault_dirs.index(self._vault_dir)

        selected, ok = QInputDialog.getItem(
            self,
            "Known Vaults",
            "Choose a remembered vault location:",
            options,
            current,
            False,
        )
        if not ok:
            return None
        if selected == "<Browse for another vault...>":
            return "browse"
        return self._normalize_vault_dir(selected)

    def _prompt_startup_mode(self):
        box = QMessageBox(self)
        box.setWindowTitle("Select Vault")
        box.setText("Choose how to start:")
        box.setInformativeText("Create a new vault or open an existing vault.")
        new_btn = box.addButton("Create New Vault", QMessageBox.AcceptRole)
        open_btn = box.addButton("Open Existing Vault", QMessageBox.ActionRole)
        cancel_btn = box.addButton(QMessageBox.Cancel)
        box.setDefaultButton(open_btn)
        box.exec()

        clicked = box.clickedButton()
        if clicked == new_btn:
            return "new"
        if clicked == open_btn:
            return "open"
        if clicked == cancel_btn:
            return None
        return None

    def _choose_existing_vault_dir(self):
        selected_known = self._select_known_vault_dir()
        if selected_known and selected_known != "browse":
            return selected_known

        box = QMessageBox(self)
        box.setWindowTitle("Open Existing Vault")
        box.setText("Select the existing vault format:")
        folder_btn = box.addButton("Unlocked Vault Folder", QMessageBox.AcceptRole)
        locked_btn = box.addButton("Locked Vault File (.locked)", QMessageBox.ActionRole)
        cancel_btn = box.addButton(QMessageBox.Cancel)
        box.setDefaultButton(folder_btn)
        box.exec()

        clicked = box.clickedButton()
        if clicked == folder_btn:
            folder = QFileDialog.getExistingDirectory(self, "Select existing vault folder")
            if not folder:
                return None
            return os.path.abspath(folder)
        if clicked == locked_btn:
            locked_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select existing .locked vault",
                filter="vault32 files (*.locked);;All files (*.*)",
            )
            if not locked_path:
                return None
            if not locked_path.lower().endswith(".locked"):
                self._alert_error("Invalid file", "Please choose a .locked vault file.")
                return None
            return os.path.abspath(locked_path[:-7])
        if clicked == cancel_btn:
            return None
        return None

    def _choose_new_vault_dir(self):
        parent = QFileDialog.getExistingDirectory(self, "Select location for the new vault")
        if not parent:
            return None

        default_name = os.path.basename(self._vault_dir) or "vault32Private"
        name = self._prompt_text("New Vault Name", "Enter a folder name for the new vault:", default_name)
        if name is None:
            return None
        name = name.strip()
        if not name:
            self._alert_error("Invalid name", "Vault folder name cannot be empty.")
            return None

        invalid_chars = '<>:"/\\|?*'
        if any(ch in name for ch in invalid_chars):
            self._alert_error("Invalid name", "Vault folder name contains invalid characters.")
            return None

        return os.path.abspath(os.path.join(parent, name))

    def _startup_vault_flow(self):
        while True:
            mode = self._prompt_startup_mode()
            if mode is None:
                self.close()
                return

            if mode == "new":
                vault_dir = self._choose_new_vault_dir()
                if not vault_dir:
                    continue
                if os.path.exists(vault_dir) or os.path.exists(vault_dir + ".locked"):
                    self._alert_error(
                        "Vault exists",
                        "A vault with this path already exists. Choose Open Existing Vault or a different new name.",
                    )
                    continue
                self._set_active_vault_dir(vault_dir)
                if self._unlock_private_vault_interactive(startup=True):
                    return
                continue

            vault_dir = self._choose_existing_vault_dir()
            if not vault_dir:
                continue
            self._set_active_vault_dir(vault_dir)
            if self._unlock_private_vault_interactive(startup=True):
                return

    def _unlock_private_vault_interactive(self, startup=False):
        os.makedirs(os.path.dirname(self._vault_dir), exist_ok=True)

        if os.path.isfile(self._vault_locked) and os.path.isdir(self._vault_dir):
            shutil.rmtree(self._vault_dir, ignore_errors=True)

        if os.path.isfile(self._vault_locked):
            while True:
                pw = self._prompt_password("Unlock Private Vault", "Enter vault password:")
                if pw is None:
                    return False
                try:
                    self._set_status("Unlocking private vault...")
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
                    self._set_task("Vault unlocked.")
                    self._vault_state_label.setText("State: Unlocked")
                    self._set_status("Private vault unlocked.")
                    self._refresh_vault_list()
                    self._update_vault_action_states()
                    return True
                except Exception as e:
                    retry = QMessageBox.question(
                        self,
                        "Unlock failed",
                        str(e) + "\n\nRetry?",
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.Yes,
                    )
                    if retry != QMessageBox.Yes:
                        return False

        if os.path.isdir(self._vault_dir):
            pw = self._prompt_new_password()
            if pw is None:
                return False
            self._vault_password = pw
            self._vault_unlocked = True
            self._touch_activity()
            self._set_task("Vault unlocked.")
            self._vault_state_label.setText("State: Unlocked")
            self._set_status("Private vault is open.")
            self._refresh_vault_list()
            self._update_vault_action_states()
            return True

        pw = self._prompt_new_password()
        if pw is None:
            return False
        os.makedirs(self._vault_dir, exist_ok=True)
        self._vault_password = pw
        self._vault_unlocked = True
        self._touch_activity()
        self._set_task("Vault unlocked.")
        self._vault_state_label.setText("State: Unlocked")
        self._set_status("Private vault ready.")
        self._refresh_vault_list()
        self._update_vault_action_states()
        if startup:
            self._alert_info("Vault ready", f"Your private vault is at:\n{self._vault_dir}")
        return True

    def _prompt_new_password(self):
        while True:
            pw1 = self._prompt_password("Set Vault Password", "Create a password for your private vault:")
            if pw1 is None:
                return None
            if not pw1:
                self._alert_error("Missing password", "Password cannot be empty.")
                continue
            pw2 = self._prompt_password("Confirm Password", "Re-enter password:")
            if pw2 is None:
                return None
            if pw1 != pw2:
                self._alert_error("Password mismatch", "Passwords do not match.")
                continue
            return pw1

    def _check_inactivity_autolock(self):
        if not self._vault_unlocked:
            return
        idle_seconds = time.time() - self._last_activity_ts
        if idle_seconds >= self._inactivity_lock_seconds:
            if self._lock_private_vault(silent=True):
                mins = self._inactivity_lock_seconds // 60
                self._set_status(f"Auto-locked after {mins} minutes of inactivity.")

    def _get_kdf_iteration_candidates(self):
        values = [self._kdf_iterations] + list(SECURITY_PROFILES.values())
        return list(dict.fromkeys(values))

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
            self._set_status("Locking private vault...")
            self._set_progress(0)
            lock_folder(
                self._vault_dir,
                self._vault_password,
                progress_cb=self._set_progress,
                kdf_iterations=self._kdf_iterations,
            )
            shutil.rmtree(self._vault_dir, ignore_errors=True)
            self._vault_unlocked = False
            self._vault_password = None
            self._vault_items = []
            self._vault_list.clear()
            self._clear_vault_details()
            self._set_task("Vault locked.")
            self._vault_state_label.setText("State: Locked")
            self._set_status("Private vault locked.")
            self._update_vault_action_states()
            return True
        except Exception as e:
            self._set_status(f"Error: {e}")
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
                self._set_status_safe("Locking private vault...")
                self._set_progress_safe(0)
                self._set_task_safe("Locking vault...")
                lock_folder(
                    vault_dir,
                    vault_password,
                    progress_cb=self._set_progress_safe,
                    kdf_iterations=self._kdf_iterations,
                )
                shutil.rmtree(vault_dir, ignore_errors=True)

                def finish():
                    self._vault_unlocked = False
                    self._vault_password = None
                    self._vault_items = []
                    self._vault_list.clear()
                    self._clear_vault_details()
                    self._update_vault_action_states()
                    self._set_task("Vault locked.")
                    self._vault_state_label.setText("State: Locked")
                    self._set_status("Private vault locked.")

                self._run_on_ui(finish)
            except Exception as e:
                self._set_status_safe(f"Error: {e}")
                self._run_on_ui(lambda: self._alert_error("Lock failed", str(e)))

        threading.Thread(target=run, daemon=True).start()

    def _manual_unlock_vault(self):
        if self._vault_unlocked:
            self._alert_info("Vault", "Vault is already unlocked.")
            return
        ok = self._unlock_private_vault_interactive(startup=False)
        if not ok:
            self._set_status("Vault remains locked.")

    def _vault_unique_path(self, name):
        base, ext = os.path.splitext(name)
        candidate = os.path.join(self._vault_dir, name)
        i = 1
        while os.path.exists(candidate):
            candidate = os.path.join(self._vault_dir, f"{base}_{i}{ext}")
            i += 1
        return candidate

    def _refresh_vault_list(self):
        self._vault_list.clear()
        self._vault_items = []
        self._clear_vault_details()

        if not self._vault_unlocked or not os.path.isdir(self._vault_dir):
            self._vault_list.addItem(QListWidgetItem("[LOCKED] Unlock vault to browse files."))
            return

        for root, dirs, files in os.walk(self._vault_dir):
            rel_root = os.path.relpath(root, self._vault_dir)
            rel_root = "" if rel_root == "." else rel_root

            for name in sorted(dirs):
                rel = os.path.join(rel_root, name) if rel_root else name
                abs_path = os.path.join(self._vault_dir, rel)
                mtime = os.path.getmtime(abs_path)
                item = {
                    "rel": rel,
                    "abs": abs_path,
                    "is_dir": True,
                    "size": 0,
                    "mtime": mtime,
                }
                self._vault_items.append(item)
                self._vault_list.addItem(QListWidgetItem(f"[DIR]  {rel}   |   {self._format_mtime(mtime)}"))

            for name in sorted(files):
                rel = os.path.join(rel_root, name) if rel_root else name
                abs_path = os.path.join(self._vault_dir, rel)
                size = os.path.getsize(abs_path)
                mtime = os.path.getmtime(abs_path)
                item = {
                    "rel": rel,
                    "abs": abs_path,
                    "is_dir": False,
                    "size": size,
                    "mtime": mtime,
                }
                self._vault_items.append(item)
                self._vault_list.addItem(
                    QListWidgetItem(f"[FILE] {rel}   |   {self._format_size(size)}   |   {self._format_mtime(mtime)}")
                )

        if not self._vault_items:
            self._vault_list.addItem(QListWidgetItem("(Vault is empty)"))

    def _clear_vault_details(self):
        self._details_name.setText("Name: -")
        self._details_type.setText("Type: -")
        self._details_size.setText("Size: -")
        self._details_mod.setText("Modified: -")
        self._details_path.setText("Path: -")

    def _selected_indices(self):
        return [idx.row() for idx in self._vault_list.selectedIndexes()]

    def _selected_targets(self):
        if not self._vault_unlocked:
            self._alert_error("Vault locked", "Unlock vault first.")
            return []
        indices = self._selected_indices()
        if not indices:
            self._alert_info("Selection required", "Select one or more entries first.")
            return []
        out = []
        for idx in indices:
            if idx >= len(self._vault_items):
                continue
            out.append(self._vault_items[idx])
        return out

    def _on_vault_selection_changed(self):
        indices = self._selected_indices()
        if len(indices) != 1:
            self._clear_vault_details()
            if len(indices) > 1:
                self._details_name.setText(f"Name: {len(indices)} items selected")
            return

        idx = indices[0]
        if idx >= len(self._vault_items):
            self._clear_vault_details()
            return
        item = self._vault_items[idx]
        self._details_name.setText(f"Name: {os.path.basename(item['rel'])}")
        self._details_type.setText(f"Type: {'Folder' if item['is_dir'] else 'File'}")
        self._details_size.setText(f"Size: {'-' if item['is_dir'] else self._format_size(item['size'])}")
        self._details_mod.setText(f"Modified: {self._format_mtime(item['mtime'])}")
        self._details_path.setText(f"Path: {item['abs']}")

    def _vault_add_files(self):
        if not self._vault_unlocked:
            self._alert_error("Vault locked", "Unlock vault first.")
            return
        files, _ = QFileDialog.getOpenFileNames(self, "Select files to add")
        if not files:
            return

        valid_files = [p for p in files if os.path.isfile(p)]
        if not valid_files:
            self._alert_error("No files", "No valid files were selected.")
            return

        total_bytes = sum(os.path.getsize(p) for p in valid_files if os.path.exists(p))

        def run():
            try:
                copied = 0
                self._set_progress_safe(0)
                self._set_task_safe("Adding files...")
                for i, src in enumerate(valid_files, start=1):
                    dst = self._vault_unique_path(os.path.basename(src))
                    self._set_status_safe(f"Adding file {i}/{len(valid_files)}: {os.path.basename(src)}")
                    with open(src, "rb") as rf, open(dst, "wb") as wf:
                        while True:
                            chunk = rf.read(1024 * 1024)
                            if not chunk:
                                break
                            wf.write(chunk)
                            copied += len(chunk)
                            if total_bytes > 0:
                                self._set_progress_safe((copied / total_bytes) * 100)
                    shutil.copystat(src, dst)
                self._run_on_ui(self._refresh_vault_list)
                self._set_progress_safe(100)
                self._set_status_safe(f"Added {len(valid_files)} file(s) to private vault.")
                self._set_task_safe(f"Added {len(valid_files)} file(s).")
            except Exception as e:
                self._set_status_safe(f"Error: {e}")
                self._run_on_ui(lambda: self._alert_error("Add files failed", str(e)))

        threading.Thread(target=run, daemon=True).start()

    def _vault_add_folder(self):
        if not self._vault_unlocked:
            self._alert_error("Vault locked", "Unlock vault first.")
            return
        src = QFileDialog.getExistingDirectory(self, "Select folder to copy into vault")
        if not src:
            return
        if os.path.normpath(src) == os.path.normpath(self._vault_dir):
            self._alert_error("Invalid folder", "Cannot copy vault into itself.")
            return
        dst = self._vault_unique_path(os.path.basename(os.path.normpath(src)))
        shutil.copytree(src, dst)
        self._refresh_vault_list()
        self._set_status("Folder added to private vault.")

    def _vault_open_selected(self):
        targets = self._selected_targets()
        if not targets:
            return
        opened = 0
        for item in targets:
            path = item["abs"]
            if not os.path.exists(path):
                continue
            os.startfile(path)
            opened += 1
        self._set_status(f"Opened {opened} item(s).")

    def _vault_rename_selected(self):
        targets = self._selected_targets()
        if len(targets) != 1:
            self._alert_info("Selection required", "Select exactly one item.")
            return
        item = targets[0]
        old_path = item["abs"]
        old_name = os.path.basename(old_path)
        new_name = self._prompt_text("Rename Item", "Enter a new name:", old_name)
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
        parent = os.path.dirname(old_path)
        new_path = os.path.normpath(os.path.join(parent, new_name))
        if os.path.exists(new_path):
            self._alert_error("Name exists", "An item with that name already exists.")
            return
        os.rename(old_path, new_path)
        self._refresh_vault_list()
        self._set_status(f"Renamed '{old_name}' to '{new_name}'.")

    def _vault_remove_selected(self):
        targets = self._selected_targets()
        if not targets:
            return
        removed = 0
        for item in targets:
            path = item["abs"]
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
                removed += 1
            elif os.path.isfile(path):
                os.remove(path)
                removed += 1
        self._refresh_vault_list()
        self._set_status(f"Removed {removed} item(s) from private vault.")

    def _open_vault_folder(self):
        if not self._vault_unlocked:
            self._alert_error("Vault locked", "Unlock vault first.")
            return
        os.startfile(self._vault_dir)

    def _update_vault_action_states(self):
        self._btn_unlock_vault.setEnabled(not self._vault_unlocked)
        self._btn_lock_vault.setEnabled(self._vault_unlocked)

    def _browse_lock_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder to lock")
        if folder:
            self._lock_path_edit.setText(folder)

    def _browse_locked_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select .locked file", filter="vault32 files (*.locked);;All files (*.*)")
        if path:
            self._unlock_path_edit.setText(path)

    def _browse_out_dir(self):
        folder = QFileDialog.getExistingDirectory(self, "Select restore destination")
        if folder:
            self._unlock_out_edit.setText(folder)

    def _do_lock(self):
        folder = self._lock_path_edit.text().strip()
        pw = self._lock_pw_edit.text()
        pw2 = self._lock_pw2_edit.text()

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
                self._set_status_safe("Encrypting...")
                self._set_progress_safe(0)
                self._set_task_safe("Tool lock in progress...")
                out = lock_folder(folder, pw, progress_cb=self._set_progress_safe, kdf_iterations=self._kdf_iterations)
                self._set_status_safe(f"Locked -> {os.path.basename(out)}")
                self._set_task_safe("Tool lock complete.")
                self._run_on_ui(lambda: self._alert_info("Locked", f"Encrypted successfully:\n{out}"))
            except Exception as e:
                self._set_status_safe(f"Error: {e}")
                self._run_on_ui(lambda: self._alert_error("Error", str(e)))

        threading.Thread(target=run, daemon=True).start()

    def _do_unlock(self):
        locked = self._unlock_path_edit.text().strip()
        out_dir = self._unlock_out_edit.text().strip()
        pw = self._unlock_pw_edit.text()

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
                self._set_status_safe("Decrypting...")
                self._set_progress_safe(0)
                self._set_task_safe("Tool unlock in progress...")
                unlock_file(
                    locked,
                    pw,
                    out_dir,
                    progress_cb=self._set_progress_safe,
                    kdf_iterations_list=self._get_kdf_iteration_candidates(),
                )
                self._set_status_safe("Decrypted successfully.")
                self._set_task_safe("Tool unlock complete.")
                self._run_on_ui(lambda: self._alert_info("Unlocked", f"Files restored to:\n{out_dir}"))
            except Exception as e:
                self._set_status_safe(f"Error: {e}")
                self._run_on_ui(lambda: self._alert_error("Error", str(e)))

        threading.Thread(target=run, daemon=True).start()

    def _format_size(self, num_bytes):
        units = ["B", "KB", "MB", "GB", "TB"]
        size = float(num_bytes)
        for unit in units:
            if size < 1024 or unit == units[-1]:
                if unit == "B":
                    return f"{int(size)} {unit}"
                return f"{size:.1f} {unit}"
            size /= 1024.0

    def _format_mtime(self, ts):
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    def closeEvent(self, event: QCloseEvent):
        if self._vault_unlocked:
            if self._lock_private_vault(silent=True):
                event.accept()
                return
            choice = QMessageBox.question(
                self,
                "Lock failed on exit",
                "Vault could not be locked. Exit anyway?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if choice == QMessageBox.Yes:
                event.accept()
            else:
                event.ignore()
            return
        event.accept()


def run_app():
    app = QApplication(sys.argv)
    win = VaultLockApp()
    win.show()
    return app.exec()
