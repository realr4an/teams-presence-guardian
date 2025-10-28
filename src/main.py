"""Entry point for the Teams Activity Keeper application."""

from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Deque, Dict, Optional, Sequence

import yaml
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from notifier import NotificationEvent, NotificationManager, NotificationManagerConfig
from presence import PresenceConfig, PresenceKeeper
from scorer import EventScorer, QuietHoursConfig, ScoreResult, ScorerConfig
from tray import AppMode, TrayController
from windows_notifications import WindowsNotificationWatcher, WindowsNotificationWatcherConfig

APP_NAME = "Teams Activity Keeper"


def _extract_value(line: str, keys: Sequence[str]) -> Optional[str]:
    """Attempt to pull a quoted value for any of the given keys from a log line."""
    for key in keys:
        pattern = rf'"{key}"\s*:\s*"([^"]+)"'
        match = re.search(pattern, line)
        if match:
            return match.group(1)

    for key in keys:
        pattern = rf"{key}\s*[:=]\s*'([^']+)'"
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def _strip_prefix(line: str) -> str:
    """Remove common timestamp prefixes from log lines."""
    trimmed = line.strip()
    candidates = ["]", " - ", " | ", "\t"]
    for token in candidates:
        idx = trimmed.find(token)
        if 0 < idx < 40:
            return trimmed[idx + len(token) :].strip()
    return trimmed


def resolve_env_placeholders(value):
    """Recursively replace ${ENV_VAR} tokens with environment variable values."""
    if isinstance(value, dict):
        return {key: resolve_env_placeholders(val) for key, val in value.items()}
    if isinstance(value, list):
        return [resolve_env_placeholders(item) for item in value]
    if isinstance(value, str):
        pattern = re.compile(r"\$\{([^}]+)\}")

        def repl(match):
            env_key = match.group(1)
            return os.getenv(env_key, "")

        return pattern.sub(repl, value)
    return value


def load_config(path: Path) -> Dict:
    """Load YAML configuration from the given path."""
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def setup_logging(log_path: Path, level: int = logging.INFO) -> None:
    """Configure logging to both file and console outputs."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(file_handler)
    root.addHandler(console_handler)


class TailHandler(FileSystemEventHandler):
    """Tail a log file for new lines and enqueue potential notifications."""

    def __init__(
        self,
        file_path: Path,
        event_queue: "queue.Queue[NotificationEvent]",
        monitor_config: Dict,
        logger: logging.Logger,
    ) -> None:
        self._file_path = file_path
        self._queue = event_queue
        self._config = monitor_config
        self._logger = logger
        self._position = file_path.stat().st_size if file_path.exists() else 0
        self._logger.debug("TailHandler initialized for %s at position %d.", file_path, self._position)

    def on_modified(self, event: FileSystemEvent) -> None:
        """Read new content when the tracked log file changes."""
        if Path(event.src_path) != self._file_path:
            return

        if not self._file_path.exists():
            return

        try:
            with self._file_path.open("r", encoding="utf-8", errors="ignore") as handle:
                handle.seek(self._position)
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    notification = self._parse_line(line)
                    if notification:
                        self._queue.put(notification)
                        self._logger.debug("Enqueued notification %s from %s.", notification.event_id, self._file_path)
                self._position = handle.tell()
        except Exception as exc:
            self._logger.error("Failed to tail %s: %s", self._file_path, exc)

    def _parse_line(self, line: str) -> Optional[NotificationEvent]:
        """Parse a raw log line into a NotificationEvent according to config."""
        parser = (self._config.get("parser") or "text").lower()
        source = self._config.get("name", "Unknown")
        metadata = {}

        if parser == "json":
            try:
                payload = json.loads(line)
                title = payload.get("title") or payload.get("subject") or source
                message = payload.get("message") or payload.get("body") or ""
                metadata = payload
            except json.JSONDecodeError:
                self._logger.debug("Skipping invalid JSON line: %s", line)
                return None
        elif parser in {"teams_legacy", "teams_modern"}:
            event = self._parse_teams_line(line=line, source=source)
            if event:
                return event
            title = source
            message = line
        else:  # default text parser
            title = source
            message = line

        return NotificationEvent(source=source, title=title, message=message, metadata=metadata)

    def _parse_teams_line(self, line: str, source: str) -> Optional[NotificationEvent]:
        """Heuristically extract interesting data from Teams log lines."""
        lowered = line.lower()
        if "notification" not in lowered and "activity" not in lowered and "message" not in lowered:
            # Skip very noisy entries (network pings, perf logs, etc.)
            return None

        sender = _extract_value(line, ["senderName", "senderDisplayName", "fromName"])
        title = _extract_value(line, ["title", "subject"]) or f"{source} activity"
        message = _extract_value(line, ["body", "message", "content"]) or _strip_prefix(line)

        metadata = {
            "sender": sender or "",
            "mentioned": "mention" in lowered or " @you" in lowered or "<at>" in lowered,
            "raw_event_hint": line[:512],
        }

        if not message:
            message = line[:512]

        return NotificationEvent(
            source=source,
            title=title,
            message=message,
            metadata=metadata,
        )


class AppState:
    """Tracks runtime state with lightweight locking."""

    def __init__(self) -> None:
        self._mode = AppMode.PRESENCE_NOTIFY
        self._presence_enabled = True
        self._lock = threading.RLock()

    @property
    def mode(self) -> AppMode:
        with self._lock:
            return self._mode

    def set_mode(self, mode: AppMode) -> None:
        with self._lock:
            self._mode = mode

    @property
    def presence_enabled(self) -> bool:
        with self._lock:
            return self._presence_enabled

    def set_presence_enabled(self, enabled: bool) -> None:
        with self._lock:
            self._presence_enabled = enabled

    def presence_allowed(self) -> bool:
        with self._lock:
            return self._presence_enabled and self._mode in {AppMode.PRESENCE_NOTIFY}

    def notifications_allowed(self) -> bool:
        with self._lock:
            return self._mode in {AppMode.NOTIFY_ONLY, AppMode.PRESENCE_NOTIFY}


class SystemIdleWatcher(threading.Thread):
    """Checks Windows idle state to toggle presence keeping intelligently."""

    def __init__(
        self,
        presence: PresenceKeeper,
        app_state: AppState,
        idle_threshold: int,
        poll_interval: int,
        logger: logging.Logger,
        stop_event: threading.Event,
    ) -> None:
        super().__init__(name="SystemIdleWatcher", daemon=True)
        self._presence = presence
        self._app_state = app_state
        self._idle_threshold = max(idle_threshold, 60)
        self._poll_interval = max(poll_interval, 5)
        self._logger = logger
        self._stop_event = stop_event

    def run(self) -> None:
        """Main loop that inspects idle time and updates the presence keeper."""
        while not self._stop_event.is_set():
            idle_seconds = get_idle_duration()
            if idle_seconds < self._poll_interval:
                self._presence.notify_user_activity()

            if self._app_state.presence_allowed():
                should_keepalive = idle_seconds >= self._idle_threshold
                self._presence.set_active(should_keepalive)
            else:
                self._presence.set_active(False)

            time.sleep(self._poll_interval)


def get_idle_duration() -> int:
    """Return the number of seconds since the last user interaction."""
    class LASTINPUTINFO(ctypes.Structure):  # type: ignore[name-defined]
        _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_ulong)]

    try:
        last_input_info = LASTINPUTINFO()
        last_input_info.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(last_input_info)) == 0:
            return 0
        millis = ctypes.windll.kernel32.GetTickCount() - last_input_info.dwTime
        return int(millis / 1000)
    except Exception:
        return 0


def build_presence_config(config: Dict) -> PresenceConfig:
    """Create a PresenceConfig from user configuration."""
    presence_section = config.get("presence", {})
    return PresenceConfig(
        keepalive_interval_seconds=presence_section.get("keepalive_interval_seconds", 45),
        allow_display_sleep=presence_section.get("allow_display_sleep", False),
        idle_timeout_seconds=presence_section.get("idle_timeout_seconds", 300),
        resume_grace_period_seconds=presence_section.get("resume_grace_period_seconds", 15),
    )


def build_scorer_config(config: Dict) -> ScorerConfig:
    """Create a ScorerConfig instance from configuration."""
    scoring = config.get("scoring", {})
    quiet_hours_dict = scoring.get("quiet_hours", {})
    quiet_hours = QuietHoursConfig(
        start=quiet_hours_dict.get("start", "22:00"),
        end=quiet_hours_dict.get("end", "07:00"),
        enabled=quiet_hours_dict.get("enabled", False),
    )
    return ScorerConfig(
        vip_list=scoring.get("vip_list", []),
        keywords=scoring.get("keywords", ["urgent", "critical", "blocker"]),
        quiet_hours=quiet_hours,
        base_threshold=scoring.get("base_threshold", 4.0),
        tier2_threshold=scoring.get("tier2_threshold", 6.0),
        tier3_threshold=scoring.get("tier3_threshold", 10.0),
        ml_model_path=scoring.get("ml_model_path"),
    )


def build_notification_config(config: Dict) -> NotificationManagerConfig:
    """Create NotificationManagerConfig from configuration."""
    notify_cfg = config.get("notifications", {})
    return NotificationManagerConfig(
        toast_enabled=notify_cfg.get("toast_enabled", True),
        repeat_minutes=notify_cfg.get("repeat_minutes", 5),
        sound_enabled=notify_cfg.get("sound_enabled", True),
        sound_file=notify_cfg.get("sound_file"),
        telegram=notify_cfg.get("telegram", {}),
        pushover=notify_cfg.get("pushover", {}),
        twilio=notify_cfg.get("twilio", {}),
        quiet_hours_enabled=notify_cfg.get("respect_quiet_hours", True),
        tier2_threshold=notify_cfg.get("tier2_threshold", 6.0),
        tier3_threshold=notify_cfg.get("tier3_threshold", 10.0),
    )


def resolve_path(path_value: str) -> Path:
    """Expand environment variables and user home markers inside a path."""
    expanded = Path(os.path.expandvars(path_value)).expanduser()
    if not expanded.is_absolute():
        return Path.cwd() / expanded
    return expanded


def build_windows_notification_config(config: Dict) -> WindowsNotificationWatcherConfig:
    """Create configuration for the Windows notification watcher."""
    section = config.get("windows_notifications", {}) or {}
    return WindowsNotificationWatcherConfig(
        enabled=section.get("enabled", False),
        db_path=section.get("db_path"),
        poll_interval_seconds=section.get("poll_interval_seconds", 5),
        app_ids=section.get("app_ids", []),
        title_overrides=section.get("title_overrides", {}),
    )


def append_alert_history(
    event: NotificationEvent,
    score: ScoreResult,
    history_path: Path,
    mode: AppMode,
) -> None:
    """Append a structured record of the alert for later feedback review."""
    history_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": time.time(),
        "event_id": event.event_id,
        "source": event.source,
        "title": event.title,
        "message": event.message[:512],
        "score": event.score,
        "reasons": event.reasons,
        "mode": mode.name,
        "quiet_hours_active": score.quiet_hours_active,
        "metadata": event.metadata,
    }
    with history_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_recent_alerts(
    history_path: Path,
    limit: int,
    filter_text: Optional[str] = None,
) -> Deque[Dict]:
    """Read the most recent alert records from the JSONL history file."""
    entries: Deque[Dict] = deque(maxlen=max(1, limit))
    if not history_path.exists():
        return entries

    filter_lower = filter_text.lower() if filter_text else None

    with history_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if filter_lower:
                haystack = " ".join(
                    [
                        str(record.get("source", "")),
                        str(record.get("title", "")),
                        str(record.get("message", "")),
                        " ".join(record.get("reasons", []) or []),
                    ]
                ).lower()
                if filter_lower not in haystack:
                    continue
            entries.append(record)
    return entries


def main() -> None:
    """Entrypoint invoked by the Windows executable or CLI."""
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--config", type=Path, default=Path(__file__).parent / "config.yaml")
    parser.add_argument(
        "--send-test-alert",
        action="store_true",
        help="Dispatch a synthetic high-priority alert to validate notification channels.",
    )
    parser.add_argument(
        "--test-alert-title",
        type=str,
        default="Teams Activity Keeper Test",
        help="Title to use when sending a synthetic test alert.",
    )
    parser.add_argument(
        "--test-alert-message",
        type=str,
        default="If you are reading this alert, your notification channel is working.",
        help="Body message for the synthetic test alert.",
    )
    parser.add_argument(
        "--mark-feedback",
        action="store_true",
        help="Record manual feedback for a past alert (requires --event-id and importance flag).",
    )
    parser.add_argument(
        "--event-id",
        type=str,
        help="The event identifier to tag when using --mark-feedback.",
    )
    feedback_group = parser.add_mutually_exclusive_group()
    feedback_group.add_argument(
        "--important",
        action="store_const",
        const=True,
        dest="feedback_importance",
        help="Mark the selected event as important.",
    )
    feedback_group.add_argument(
        "--not-important",
        action="store_const",
        const=False,
        dest="feedback_importance",
        help="Mark the selected event as not important.",
    )
    parser.add_argument(
        "--feedback-note",
        type=str,
        default="",
        help="Optional note to store alongside manual feedback entries.",
    )
    parser.set_defaults(feedback_importance=None)
    parser.add_argument(
        "--list-alerts",
        action="store_true",
        help="Print recent alerts from the history log and exit.",
    )
    parser.add_argument(
        "--alerts-limit",
        type=int,
        default=20,
        help="How many alert entries to show when using --list-alerts (default: 20).",
    )
    parser.add_argument(
        "--alerts-filter",
        type=str,
        help="Optional case-insensitive filter applied to source/title/message/reasons when listing alerts.",
    )
    args = parser.parse_args()

    config_path = args.config if args.config.is_absolute() else (Path.cwd() / args.config)
    raw_config = load_config(config_path)
    config = resolve_env_placeholders(raw_config)
    logging_section = config.get("logging", {}) or {}
    log_path = resolve_path(logging_section.get("path", "logs/teams_activity_keeper.log"))
    alerts_path = resolve_path(logging_section.get("alerts_path", "logs/alerts.jsonl"))
    setup_logging(log_path)
    logger = logging.getLogger("tak.main")

    if args.list_alerts:
        alerts = load_recent_alerts(alerts_path, args.alerts_limit, args.alerts_filter)
        if not alerts:
            logger.info("No alert history found at %s.", alerts_path)
        else:
            logger.info("Showing %s most recent alerts from %s:", len(alerts), alerts_path)
            for entry in alerts:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.get("timestamp", time.time())))
                reasons = ", ".join(entry.get("reasons") or [])
                logger.info(
                    "[%s] %s | %s | score=%.1f | reasons=%s | mode=%s",
                    timestamp,
                    entry.get("source", "Unknown"),
                    entry.get("title"),
                    entry.get("score", 0.0),
                    reasons or "n/a",
                    entry.get("mode", "N/A"),
                )
        return

    feedback_path = resolve_path(config.get("feedback", {}).get("path", "logs/feedback.csv"))

    logger.info("%s starting up.", APP_NAME)
    presence_config = build_presence_config(config)
    scorer_config = build_scorer_config(config)
    notification_config = build_notification_config(config)

    if args.send_test_alert:
        notifier = NotificationManager(notification_config, logger=logging.getLogger("tak.notifier"))
        test_event = NotificationEvent(
            source="Test Harness",
            title=args.test_alert_title,
            message=args.test_alert_message,
            score=max(notification_config.tier3_threshold, scorer_config.tier3_threshold) + 1,
            reasons=["Manual test alert"],
        )
        notifier.handle(test_event, quiet_hours_active=False)
        logger.info(
            "Test alert dispatched (id=%s, title=%s). Review your notification channels for delivery.",
            test_event.event_id,
            test_event.title,
        )
        return

    if args.mark_feedback:
        if not args.event_id:
            logger.error("Cannot mark feedback without --event-id.")
            return
        if args.feedback_importance is None:
            logger.error("Specify --important or --not-important when using --mark-feedback.")
            return
        feedback_notifier = NotificationManager(
            notification_config,
            logger=logging.getLogger("tak.notifier"),
        )
        note = args.feedback_note.strip() or "manual_cli"
        feedback_notifier.record_feedback(
            args.event_id,
            was_important=args.feedback_importance,
            storage_path=feedback_path,
            note=note,
        )
        logger.info(
            "Feedback logged for %s (important=%s, note=%s).",
            args.event_id,
            args.feedback_importance,
            note,
        )
        return

    # Instantiate subsystems
    presence = PresenceKeeper(presence_config, logger=logging.getLogger("tak.presence"))
    scorer = EventScorer(scorer_config, logger=logging.getLogger("tak.scorer"))
    notifier = NotificationManager(notification_config, logger=logging.getLogger("tak.notifier"))
    app_state = AppState()

    # Start presence keeper
    presence.start()

    stop_event = threading.Event()
    idle_watcher = SystemIdleWatcher(
        presence=presence,
        app_state=app_state,
        idle_threshold=presence_config.idle_timeout_seconds,
        poll_interval=presence_config.keepalive_interval_seconds,
        logger=logging.getLogger("tak.idle"),
        stop_event=stop_event,
    )
    idle_watcher.start()

    event_queue: "queue.Queue[NotificationEvent]" = queue.Queue()
    observers = []
    for monitor in config.get("monitors", []):
        path_str = monitor.get("path")
        if not path_str:
            continue
        file_path = resolve_path(path_str)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        handler_logger = logging.getLogger(f"tak.monitor.{monitor.get('name','unknown')}")
        handler = TailHandler(file_path=file_path, event_queue=event_queue, monitor_config=monitor, logger=handler_logger)
        observer = Observer()
        observer.schedule(handler, str(file_path.parent), recursive=False)
        observer.start()
        observers.append(observer)
        handler_logger.info("Watching %s for updates.", file_path)

    windows_notifications_cfg = build_windows_notification_config(config)
    win_notification_watcher: Optional[WindowsNotificationWatcher] = None
    if windows_notifications_cfg.enabled:
        win_notification_watcher = WindowsNotificationWatcher(
            event_queue=event_queue,
            config=windows_notifications_cfg,
            stop_event=stop_event,
            logger=logging.getLogger("tak.win_notif"),
        )
        win_notification_watcher.start()

    settings_script = Path(__file__).parent / "settings_ui.py"

    def launch_settings() -> None:
        """Open the settings GUI in a separate process."""
        candidates = []
        if settings_script.exists():
            candidates.append([sys.executable, str(settings_script), "--config", str(config_path)])

        exe_dir = Path(sys.executable).parent
        for name in ("TeamsActivityKeeperSettings.exe", "settings_ui.exe"):
            candidate = exe_dir / name
            if candidate.exists():
                candidates.append([str(candidate), "--config", str(config_path)])

        if not candidates:
            logger.error("Settings UI not found. Ensure settings_ui.py or a packaged settings executable is present.")
            return

        command = candidates[0]
        try:
            subprocess.Popen(command, close_fds=False)
        except Exception as exc:
            logger.error("Failed to launch settings UI: %s", exc)

    tray = TrayController(
        on_mode_change=lambda mode: app_state.set_mode(mode),
        on_toggle_presence=lambda enabled: app_state.set_presence_enabled(enabled),
        on_quit=lambda: stop_event.set(),
        on_open_settings=launch_settings,
        logger=logging.getLogger("tak.tray"),
    )
    tray.start()
    tray.update_tooltip("Presence+Notify | Idle monitoring active")

    def handle_signal(signum, frame):
        logger.info("Signal %s received; shutting down.", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)


    try:
        while not stop_event.is_set():
            try:
                event = event_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if not app_state.notifications_allowed():
                logger.debug("Notifications disabled in current mode; dropping event %s.", event.event_id)
                continue

            score_result = scorer.score(event)
            event.score = score_result.score
            event.reasons = score_result.reasons

            if score_result.score < scorer_config.base_threshold:
                logger.debug("Event %s score %.1f below threshold.", event.event_id, score_result.score)
                continue

            notifier.handle(event, quiet_hours_active=score_result.quiet_hours_active)
            append_alert_history(event, score_result, alerts_path, app_state.mode)
            tray.update_tooltip(f"{app_state.mode.name.title()} | Last alert: {event.title}")

            if config.get("feedback", {}).get("auto_log", False):
                notifier.record_feedback(
                    event.event_id,
                    was_important=True,
                    storage_path=feedback_path,
                    note="auto_log",
                )

    except KeyboardInterrupt:
        stop_event.set()
    finally:
        logger.info("Shutting down...")
        tray.shutdown()
        presence.stop()
        stop_event.set()
        for observer in observers:
            observer.stop()
            observer.join(timeout=5)
        if win_notification_watcher:
            win_notification_watcher.join(timeout=5)
        idle_watcher.join(timeout=5)
        logger.info("%s stopped.", APP_NAME)


if __name__ == "__main__":
    main()

