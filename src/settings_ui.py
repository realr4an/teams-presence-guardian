"""Graphical configuration editor for Teams Activity Keeper."""

from __future__ import annotations

import argparse
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from typing import Dict, List, Optional

import yaml


class SettingsApp:
    """Tkinter-based editor for Teams Activity Keeper settings."""

    def __init__(self, root: tk.Tk, config_path: Path) -> None:
        self._root = root
        self._config_path = config_path
        self._config = self._load_config()

        self._root.title("Teams Activity Keeper Settings")
        self._root.geometry("720x640")
        self._root.minsize(640, 600)

        self._build_widgets()
        self._populate_fields()

    def run(self) -> None:
        """Start the Tkinter event loop."""
        self._root.mainloop()

    def _load_config(self) -> Dict:
        """Read YAML configuration or return defaults."""
        if not self._config_path.exists():
            messagebox.showwarning("Configuration", f"Config file not found: {self._config_path}")
            return {}
        with self._config_path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}

    def _build_widgets(self) -> None:
        """Set up notebook tabs and controls."""
        notebook = ttk.Notebook(self._root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self._presence_tab = ttk.Frame(notebook)
        self._scoring_tab = ttk.Frame(notebook)
        self._notifications_tab = ttk.Frame(notebook)
        self._monitors_tab = ttk.Frame(notebook)
        self._feedback_tab = ttk.Frame(notebook)

        notebook.add(self._presence_tab, text="Presence")
        notebook.add(self._scoring_tab, text="Scoring")
        notebook.add(self._notifications_tab, text="Notifications")
        notebook.add(self._monitors_tab, text="Monitors")
        notebook.add(self._feedback_tab, text="Feedback")

        self._build_presence_tab()
        self._build_scoring_tab()
        self._build_notifications_tab()
        self._build_monitors_tab()
        self._build_feedback_tab()

        btn_frame = ttk.Frame(self._root)
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        ttk.Button(btn_frame, text="Reload", command=self._reload).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Save", command=self._save).pack(side=tk.RIGHT, padx=(0, 5))
        ttk.Button(btn_frame, text="Save & Close", command=self._save_and_close).pack(side=tk.RIGHT, padx=(0, 5))

    def _build_presence_tab(self) -> None:
        """Create inputs for presence-related settings."""
        self._presence_vars = {
            "keepalive_interval_seconds": tk.StringVar(),
            "allow_display_sleep": tk.BooleanVar(),
            "idle_timeout_seconds": tk.StringVar(),
            "resume_grace_period_seconds": tk.StringVar(),
        }

        ttk.Label(self._presence_tab, text="Keepalive interval (seconds)").grid(row=0, column=0, sticky="w", padx=10, pady=8)
        ttk.Entry(self._presence_tab, textvariable=self._presence_vars["keepalive_interval_seconds"]).grid(row=0, column=1, padx=10, pady=8)

        ttk.Label(self._presence_tab, text="Idle timeout before keepalive (seconds)").grid(row=1, column=0, sticky="w", padx=10, pady=8)
        ttk.Entry(self._presence_tab, textvariable=self._presence_vars["idle_timeout_seconds"]).grid(row=1, column=1, padx=10, pady=8)

        ttk.Label(self._presence_tab, text="Resume grace period (seconds)").grid(row=2, column=0, sticky="w", padx=10, pady=8)
        ttk.Entry(self._presence_tab, textvariable=self._presence_vars["resume_grace_period_seconds"]).grid(row=2, column=1, padx=10, pady=8)

        ttk.Checkbutton(
            self._presence_tab,
            text="Allow display to sleep",
            variable=self._presence_vars["allow_display_sleep"],
        ).grid(row=3, column=0, columnspan=2, sticky="w", padx=10, pady=8)

        for i in range(2):
            self._presence_tab.columnconfigure(i, weight=1)

    def _build_scoring_tab(self) -> None:
        """Create inputs for scoring settings."""
        self._scoring_vars = {
            "base_threshold": tk.StringVar(),
            "tier2_threshold": tk.StringVar(),
            "tier3_threshold": tk.StringVar(),
            "vip_list": tk.StringVar(),
            "keywords": tk.StringVar(),
            "quiet_hours_enabled": tk.BooleanVar(),
            "quiet_hours_start": tk.StringVar(),
            "quiet_hours_end": tk.StringVar(),
            "ml_model_path": tk.StringVar(),
        }

        fields = [
            ("Base threshold", "base_threshold"),
            ("Tier 2 threshold", "tier2_threshold"),
            ("Tier 3 threshold", "tier3_threshold"),
            ("VIP list (comma separated)", "vip_list"),
            ("Keywords (comma separated)", "keywords"),
        ]
        for idx, (label, key) in enumerate(fields):
            ttk.Label(self._scoring_tab, text=label).grid(row=idx, column=0, sticky="w", padx=10, pady=6)
            ttk.Entry(self._scoring_tab, textvariable=self._scoring_vars[key]).grid(row=idx, column=1, padx=10, pady=6, sticky="ew")

        ttk.Checkbutton(
            self._scoring_tab,
            text="Enable quiet hours",
            variable=self._scoring_vars["quiet_hours_enabled"],
        ).grid(row=len(fields), column=0, columnspan=2, sticky="w", padx=10, pady=6)

        ttk.Label(self._scoring_tab, text="Quiet hours start (HH:MM)").grid(row=len(fields) + 1, column=0, sticky="w", padx=10, pady=6)
        ttk.Entry(self._scoring_tab, textvariable=self._scoring_vars["quiet_hours_start"]).grid(row=len(fields) + 1, column=1, padx=10, pady=6, sticky="ew")

        ttk.Label(self._scoring_tab, text="Quiet hours end (HH:MM)").grid(row=len(fields) + 2, column=0, sticky="w", padx=10, pady=6)
        ttk.Entry(self._scoring_tab, textvariable=self._scoring_vars["quiet_hours_end"]).grid(row=len(fields) + 2, column=1, padx=10, pady=6, sticky="ew")

        ttk.Label(self._scoring_tab, text="ML model path (optional)").grid(row=len(fields) + 3, column=0, sticky="w", padx=10, pady=6)
        ml_frame = ttk.Frame(self._scoring_tab)
        ml_frame.grid(row=len(fields) + 3, column=1, padx=10, pady=6, sticky="ew")
        ttk.Entry(ml_frame, textvariable=self._scoring_vars["ml_model_path"]).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(ml_frame, text="Browse", command=self._browse_model).pack(side=tk.LEFT, padx=(5, 0))

        self._scoring_tab.columnconfigure(1, weight=1)

    def _build_notifications_tab(self) -> None:
        """Create inputs for notification settings."""
        self._notifications_vars = {
            "toast_enabled": tk.BooleanVar(),
            "repeat_minutes": tk.StringVar(),
            "sound_enabled": tk.BooleanVar(),
            "sound_file": tk.StringVar(),
            "respect_quiet_hours": tk.BooleanVar(),
            "telegram_enabled": tk.BooleanVar(),
            "telegram_bot_token": tk.StringVar(),
            "telegram_chat_id": tk.StringVar(),
            "pushover_enabled": tk.BooleanVar(),
            "pushover_api_token": tk.StringVar(),
            "pushover_user_key": tk.StringVar(),
            "twilio_enabled": tk.BooleanVar(),
            "twilio_account_sid": tk.StringVar(),
            "twilio_auth_token": tk.StringVar(),
            "twilio_from_number": tk.StringVar(),
            "twilio_to_number": tk.StringVar(),
        }

        ttk.Checkbutton(
            self._notifications_tab,
            text="Toast notifications",
            variable=self._notifications_vars["toast_enabled"],
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=10, pady=6)

        ttk.Label(self._notifications_tab, text="Repeat reminder every (minutes)").grid(row=1, column=0, sticky="w", padx=10, pady=6)
        ttk.Entry(self._notifications_tab, textvariable=self._notifications_vars["repeat_minutes"]).grid(row=1, column=1, padx=10, pady=6, sticky="ew")

        ttk.Checkbutton(
            self._notifications_tab,
            text="Enable sound",
            variable=self._notifications_vars["sound_enabled"],
        ).grid(row=2, column=0, columnspan=2, sticky="w", padx=10, pady=6)

        sound_frame = ttk.Frame(self._notifications_tab)
        sound_frame.grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=6)
        ttk.Entry(sound_frame, textvariable=self._notifications_vars["sound_file"]).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(sound_frame, text="Browse", command=self._browse_sound).pack(side=tk.LEFT, padx=(5, 0))
        ttk.Checkbutton(
            self._notifications_tab,
            text="Respect quiet hours",
            variable=self._notifications_vars["respect_quiet_hours"],
        ).grid(row=4, column=0, columnspan=2, sticky="w", padx=10, pady=6)

        ttk.Separator(self._notifications_tab).grid(row=5, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        ttk.Label(self._notifications_tab, text="Telegram").grid(row=6, column=0, sticky="w", padx=10, pady=4)
        ttk.Checkbutton(
            self._notifications_tab,
            text="Enable Telegram push",
            variable=self._notifications_vars["telegram_enabled"],
        ).grid(row=6, column=1, sticky="w", padx=10, pady=4)
        ttk.Label(self._notifications_tab, text="Bot token").grid(row=7, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(self._notifications_tab, textvariable=self._notifications_vars["telegram_bot_token"]).grid(row=7, column=1, padx=10, pady=4, sticky="ew")
        ttk.Label(self._notifications_tab, text="Chat ID").grid(row=8, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(self._notifications_tab, textvariable=self._notifications_vars["telegram_chat_id"]).grid(row=8, column=1, padx=10, pady=4, sticky="ew")

        ttk.Separator(self._notifications_tab).grid(row=9, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        ttk.Label(self._notifications_tab, text="Pushover").grid(row=10, column=0, sticky="w", padx=10, pady=4)
        ttk.Checkbutton(
            self._notifications_tab,
            text="Enable Pushover",
            variable=self._notifications_vars["pushover_enabled"],
        ).grid(row=10, column=1, sticky="w", padx=10, pady=4)
        ttk.Label(self._notifications_tab, text="API token").grid(row=11, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(self._notifications_tab, textvariable=self._notifications_vars["pushover_api_token"]).grid(row=11, column=1, padx=10, pady=4, sticky="ew")
        ttk.Label(self._notifications_tab, text="User key").grid(row=12, column=0, sticky="w", padx=10, pady=4)
        ttk.Entry(self._notifications_tab, textvariable=self._notifications_vars["pushover_user_key"]).grid(row=12, column=1, padx=10, pady=4, sticky="ew")

        ttk.Separator(self._notifications_tab).grid(row=13, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        ttk.Label(self._notifications_tab, text="Twilio").grid(row=14, column=0, sticky="w", padx=10, pady=4)
        ttk.Checkbutton(
            self._notifications_tab,
            text="Enable Twilio call",
            variable=self._notifications_vars["twilio_enabled"],
        ).grid(row=14, column=1, sticky="w", padx=10, pady=4)
        labels = [
            ("Account SID", "twilio_account_sid"),
            ("Auth token", "twilio_auth_token"),
            ("From number", "twilio_from_number"),
            ("To number", "twilio_to_number"),
        ]
        for offset, (label, key) in enumerate(labels, start=15):
            ttk.Label(self._notifications_tab, text=label).grid(row=offset, column=0, sticky="w", padx=10, pady=4)
            ttk.Entry(self._notifications_tab, textvariable=self._notifications_vars[key]).grid(row=offset, column=1, padx=10, pady=4, sticky="ew")

        hint_row = 15 + len(labels)
        ttk.Label(
            self._notifications_tab,
            text="Tip: Use ${ENV_VAR} tokens (e.g. ${TELEGRAM_BOT_TOKEN}) to load secrets from the environment.",
            foreground="gray",
            wraplength=360,
        ).grid(row=hint_row, column=0, columnspan=2, sticky="w", padx=10, pady=(6, 0))

        self._notifications_tab.columnconfigure(1, weight=1)

    def _build_monitors_tab(self) -> None:
        """Create controls for managing monitored log paths."""
        self._monitors: List[Dict] = list(self._config.get("monitors", []))
        self._monitor_list = tk.Listbox(self._monitors_tab, exportselection=False, height=10)
        self._monitor_list.grid(row=0, column=0, rowspan=5, sticky="nsew", padx=(10, 5), pady=10)
        self._monitor_list.bind("<<ListboxSelect>>", self._on_monitor_select)

        control_frame = ttk.Frame(self._monitors_tab)
        control_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 10), pady=10)

        self._monitor_vars = {
            "name": tk.StringVar(),
            "path": tk.StringVar(),
            "parser": tk.StringVar(),
        }

        ttk.Label(control_frame, text="Name").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(control_frame, textvariable=self._monitor_vars["name"]).grid(row=0, column=1, sticky="ew", pady=4)

        ttk.Label(control_frame, text="Path").grid(row=1, column=0, sticky="w", pady=4)
        path_frame = ttk.Frame(control_frame)
        path_frame.grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Entry(path_frame, textvariable=self._monitor_vars["path"]).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(path_frame, text="Browse", command=self._browse_monitor_path).pack(side=tk.LEFT, padx=(5, 0))

        ttk.Label(control_frame, text="Parser (text/json)").grid(row=2, column=0, sticky="w", pady=4)
        parser_entry = ttk.Combobox(control_frame, textvariable=self._monitor_vars["parser"], values=["text", "json"], state="readonly")
        parser_entry.grid(row=2, column=1, sticky="ew", pady=4)

        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10, sticky="ew")
        ttk.Button(button_frame, text="Add / Update", command=self._add_or_update_monitor).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete", command=self._delete_monitor).pack(side=tk.LEFT, padx=5)

        self._monitors_tab.columnconfigure(0, weight=1)
        self._monitors_tab.columnconfigure(1, weight=2)
        self._monitors_tab.rowconfigure(0, weight=1)

    def _build_feedback_tab(self) -> None:
        """Create inputs for feedback logging settings."""
        self._feedback_vars = {
            "path": tk.StringVar(),
            "auto_log": tk.BooleanVar(),
        }

        ttk.Label(self._feedback_tab, text="Feedback CSV path").grid(row=0, column=0, sticky="w", padx=10, pady=8)
        frame = ttk.Frame(self._feedback_tab)
        frame.grid(row=0, column=1, sticky="ew", padx=10, pady=8)
        ttk.Entry(frame, textvariable=self._feedback_vars["path"]).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(frame, text="Browse", command=self._browse_feedback).pack(side=tk.LEFT, padx=(5, 0))

        ttk.Checkbutton(
            self._feedback_tab,
            text="Automatically record important alerts",
            variable=self._feedback_vars["auto_log"],
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=10, pady=8)

        self._feedback_tab.columnconfigure(1, weight=1)

    def _populate_fields(self) -> None:
        """Fill GUI controls with current configuration values."""
        presence_cfg = self._config.get("presence", {})
        self._presence_vars["keepalive_interval_seconds"].set(str(presence_cfg.get("keepalive_interval_seconds", 45)))
        self._presence_vars["allow_display_sleep"].set(bool(presence_cfg.get("allow_display_sleep", False)))
        self._presence_vars["idle_timeout_seconds"].set(str(presence_cfg.get("idle_timeout_seconds", 300)))
        self._presence_vars["resume_grace_period_seconds"].set(str(presence_cfg.get("resume_grace_period_seconds", 20)))

        scoring_cfg = self._config.get("scoring", {})
        self._scoring_vars["base_threshold"].set(str(scoring_cfg.get("base_threshold", 4.0)))
        self._scoring_vars["tier2_threshold"].set(str(scoring_cfg.get("tier2_threshold", 6.0)))
        self._scoring_vars["tier3_threshold"].set(str(scoring_cfg.get("tier3_threshold", 10.0)))
        self._scoring_vars["vip_list"].set(", ".join(scoring_cfg.get("vip_list", [])))
        self._scoring_vars["keywords"].set(", ".join(scoring_cfg.get("keywords", [])))
        quiet_cfg = scoring_cfg.get("quiet_hours", {})
        self._scoring_vars["quiet_hours_enabled"].set(bool(quiet_cfg.get("enabled", False)))
        self._scoring_vars["quiet_hours_start"].set(quiet_cfg.get("start", "22:00"))
        self._scoring_vars["quiet_hours_end"].set(quiet_cfg.get("end", "07:00"))
        self._scoring_vars["ml_model_path"].set(scoring_cfg.get("ml_model_path") or "")

        notify_cfg = self._config.get("notifications", {})
        self._notifications_vars["toast_enabled"].set(bool(notify_cfg.get("toast_enabled", True)))
        self._notifications_vars["repeat_minutes"].set(str(notify_cfg.get("repeat_minutes", 5)))
        self._notifications_vars["sound_enabled"].set(bool(notify_cfg.get("sound_enabled", True)))
        self._notifications_vars["sound_file"].set(notify_cfg.get("sound_file") or "")
        self._notifications_vars["respect_quiet_hours"].set(bool(notify_cfg.get("respect_quiet_hours", True)))

        telegram_cfg = notify_cfg.get("telegram", {})
        self._notifications_vars["telegram_enabled"].set(bool(telegram_cfg.get("enabled", False)))
        self._notifications_vars["telegram_bot_token"].set(telegram_cfg.get("bot_token", ""))
        self._notifications_vars["telegram_chat_id"].set(telegram_cfg.get("chat_id", ""))

        pushover_cfg = notify_cfg.get("pushover", {})
        self._notifications_vars["pushover_enabled"].set(bool(pushover_cfg.get("enabled", False)))
        self._notifications_vars["pushover_api_token"].set(pushover_cfg.get("api_token", ""))
        self._notifications_vars["pushover_user_key"].set(pushover_cfg.get("user_key", ""))

        twilio_cfg = notify_cfg.get("twilio", {})
        self._notifications_vars["twilio_enabled"].set(bool(twilio_cfg.get("enabled", False)))
        self._notifications_vars["twilio_account_sid"].set(twilio_cfg.get("account_sid", ""))
        self._notifications_vars["twilio_auth_token"].set(twilio_cfg.get("auth_token", ""))
        self._notifications_vars["twilio_from_number"].set(twilio_cfg.get("from_number", ""))
        self._notifications_vars["twilio_to_number"].set(twilio_cfg.get("to_number", ""))

        feedback_cfg = self._config.get("feedback", {})
        self._feedback_vars["path"].set(feedback_cfg.get("path", "logs/feedback.csv"))
        self._feedback_vars["auto_log"].set(bool(feedback_cfg.get("auto_log", False)))

        self._refresh_monitor_list()

    def _gather_config(self) -> Dict:
        """Collect the current form values into a configuration dict."""
        presence = {
            "keepalive_interval_seconds": int(self._presence_vars["keepalive_interval_seconds"].get() or 45),
            "allow_display_sleep": bool(self._presence_vars["allow_display_sleep"].get()),
            "idle_timeout_seconds": int(self._presence_vars["idle_timeout_seconds"].get() or 300),
            "resume_grace_period_seconds": int(self._presence_vars["resume_grace_period_seconds"].get() or 20),
        }

        vip_list = [v.strip() for v in self._scoring_vars["vip_list"].get().split(",") if v.strip()]
        keywords = [k.strip() for k in self._scoring_vars["keywords"].get().split(",") if k.strip()]
        scoring = {
            "base_threshold": float(self._scoring_vars["base_threshold"].get() or 4.0),
            "tier2_threshold": float(self._scoring_vars["tier2_threshold"].get() or 6.0),
            "tier3_threshold": float(self._scoring_vars["tier3_threshold"].get() or 10.0),
            "vip_list": vip_list,
            "keywords": keywords,
            "quiet_hours": {
                "enabled": bool(self._scoring_vars["quiet_hours_enabled"].get()),
                "start": self._scoring_vars["quiet_hours_start"].get() or "22:00",
                "end": self._scoring_vars["quiet_hours_end"].get() or "07:00",
            },
            "ml_model_path": self._scoring_vars["ml_model_path"].get() or None,
        }

        notifications = {
            "toast_enabled": bool(self._notifications_vars["toast_enabled"].get()),
            "repeat_minutes": int(self._notifications_vars["repeat_minutes"].get() or 5),
            "sound_enabled": bool(self._notifications_vars["sound_enabled"].get()),
            "sound_file": self._notifications_vars["sound_file"].get() or None,
            "respect_quiet_hours": bool(self._notifications_vars["respect_quiet_hours"].get()),
            "telegram": {
                "enabled": bool(self._notifications_vars["telegram_enabled"].get()),
                "bot_token": self._notifications_vars["telegram_bot_token"].get(),
                "chat_id": self._notifications_vars["telegram_chat_id"].get(),
            },
            "pushover": {
                "enabled": bool(self._notifications_vars["pushover_enabled"].get()),
                "api_token": self._notifications_vars["pushover_api_token"].get(),
                "user_key": self._notifications_vars["pushover_user_key"].get(),
            },
            "twilio": {
                "enabled": bool(self._notifications_vars["twilio_enabled"].get()),
                "account_sid": self._notifications_vars["twilio_account_sid"].get(),
                "auth_token": self._notifications_vars["twilio_auth_token"].get(),
                "from_number": self._notifications_vars["twilio_from_number"].get(),
                "to_number": self._notifications_vars["twilio_to_number"].get(),
            },
        }

        cfg = dict(self._config)
        cfg["presence"] = presence
        cfg["scoring"] = scoring
        cfg["notifications"] = notifications
        cfg["monitors"] = list(self._monitors)
        cfg["feedback"] = {
            "path": self._feedback_vars["path"].get(),
            "auto_log": bool(self._feedback_vars["auto_log"].get()),
        }

        if "logging" not in cfg:
            cfg["logging"] = {"path": "logs/teams_activity_keeper.log"}

        return cfg

    def _save(self) -> None:
        """Persist the edited configuration to disk."""
        try:
            config = self._gather_config()
        except ValueError as exc:
            messagebox.showerror("Invalid value", str(exc))
            return

        with self._config_path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(config, handle, sort_keys=False)
        messagebox.showinfo("Saved", f"Configuration saved to {self._config_path}")
        self._config = config

    def _save_and_close(self) -> None:
        """Save configuration changes and close the window."""
        self._save()
        self._root.destroy()

    def _reload(self) -> None:
        """Reload configuration from disk."""
        self._config = self._load_config()
        self._populate_fields()

    def _browse_model(self) -> None:
        """Open a file dialog to select an ML model file."""
        path = filedialog.askopenfilename(title="Select model file", filetypes=[("Pickle files", "*.pkl"), ("All files", "*.*")])
        if path:
            self._scoring_vars["ml_model_path"].set(path)

    def _browse_sound(self) -> None:
        """Select a custom notification sound file."""
        path = filedialog.askopenfilename(title="Select sound file", filetypes=[("WAV files", "*.wav"), ("All files", "*.*")])
        if path:
            self._notifications_vars["sound_file"].set(path)

    def _browse_monitor_path(self) -> None:
        """Choose a file path to monitor."""
        path = filedialog.askopenfilename(title="Select log file")
        if path:
            self._monitor_vars["path"].set(path)

    def _browse_feedback(self) -> None:
        """Select a CSV file path for feedback logs."""
        path = filedialog.asksaveasfilename(title="Select feedback file", defaultextension=".csv", filetypes=[("CSV", "*.csv"), ("All files", "*.*")])
        if path:
            self._feedback_vars["path"].set(path)

    def _refresh_monitor_list(self) -> None:
        """Update the monitor listbox."""
        self._monitor_list.delete(0, tk.END)
        for monitor in self._monitors:
            self._monitor_list.insert(tk.END, monitor.get("name", monitor.get("path", "Unnamed")))
        self._monitor_vars["name"].set("")
        self._monitor_vars["path"].set("")
        self._monitor_vars["parser"].set("")

    def _on_monitor_select(self, event) -> None:
        """Populate fields based on the selected monitor."""
        selection = self._monitor_list.curselection()
        if not selection:
            return
        monitor = self._monitors[selection[0]]
        self._monitor_vars["name"].set(monitor.get("name", ""))
        self._monitor_vars["path"].set(monitor.get("path", ""))
        self._monitor_vars["parser"].set(monitor.get("parser", "text"))

    def _add_or_update_monitor(self) -> None:
        """Add a new monitor or update the selected one."""
        name = self._monitor_vars["name"].get().strip()
        path = self._monitor_vars["path"].get().strip()
        parser = self._monitor_vars["parser"].get().strip() or "text"

        if not path:
            messagebox.showerror("Monitor", "Path is required.")
            return

        monitor = {"name": name or path, "path": path, "parser": parser}
        selection = self._monitor_list.curselection()
        if selection:
            self._monitors[selection[0]] = monitor
        else:
            self._monitors.append(monitor)
        self._refresh_monitor_list()

    def _delete_monitor(self) -> None:
        """Remove the selected monitor."""
        selection = self._monitor_list.curselection()
        if not selection:
            return
        idx = selection[0]
        del self._monitors[idx]
        self._refresh_monitor_list()


def run_gui(config_path: Path) -> None:
    """Launch the settings GUI."""
    root = tk.Tk()
    app = SettingsApp(root, config_path=config_path)
    app.run()


def main() -> None:
    """Parse arguments and open the settings window."""
    parser = argparse.ArgumentParser(description="Teams Activity Keeper Settings")
    parser.add_argument("--config", type=Path, default=Path("src/config.yaml"))
    args = parser.parse_args()
    config_path = args.config.resolve()
    run_gui(config_path)


if __name__ == "__main__":
    main()
