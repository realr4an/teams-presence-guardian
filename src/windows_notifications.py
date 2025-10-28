"""Windows notification watcher that polls the Action Center database."""

from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from notifier import NotificationEvent

DEFAULT_DB_PATH = "%LOCALAPPDATA%/Microsoft/Windows/Notifications/wpndatabase.db"


@dataclass
class WindowsNotificationWatcherConfig:
    """Configuration for the Windows notification polling watcher."""

    enabled: bool = False
    db_path: str = DEFAULT_DB_PATH
    poll_interval_seconds: int = 5
    app_ids: Sequence[str] = field(default_factory=list)
    title_overrides: Dict[str, str] = field(default_factory=dict)
    max_cache_size: int = 5000


class WindowsNotificationWatcher(threading.Thread):
    """Polls the Windows notification database for new toast notifications."""

    def __init__(
        self,
        event_queue: "queue.Queue[NotificationEvent]",
        config: WindowsNotificationWatcherConfig,
        stop_event: threading.Event,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        super().__init__(name="WindowsNotificationWatcher", daemon=True)
        import queue  # Local import to avoid circular dependency typing issues

        if not isinstance(event_queue, queue.Queue):
            raise TypeError("event_queue must be a queue.Queue instance.")

        self._queue: "queue.Queue[NotificationEvent]" = event_queue
        self._config = config
        self._stop_event = stop_event
        self._logger = logger or logging.getLogger(__name__)
        self._last_notification_id: int = 0
        self._known_ids: List[int] = []
        self._missing_db_logged = False

    def run(self) -> None:
        """Main polling loop."""
        poll_interval = max(2, self._config.poll_interval_seconds)
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as exc:  # pragma: no cover - defensive logging
                self._logger.error("Windows notification poll failed: %s", exc)
            finally:
                self._stop_event.wait(poll_interval)

    def _poll_once(self) -> None:
        """Process notifications inserted since the last poll."""
        db_path = resolve_env_path(self._config.db_path)
        if not db_path.exists():
            if not self._missing_db_logged:
                self._logger.warning("Windows notification DB not found at %s", db_path)
                self._missing_db_logged = True
            return
        self._missing_db_logged = False

        temp_copy = Path(tempfile.gettempdir()) / f"tak_win_notif_{uuid.uuid4().hex}.db"
        try:
            shutil.copyfile(db_path, temp_copy)
        except PermissionError:
            self._logger.debug("Unable to copy notification DB (permission denied): %s", db_path)
            return
        except OSError as exc:
            self._logger.debug("Unable to copy notification DB: %s", exc)
            return

        try:
            connection = sqlite3.connect(f"file:{temp_copy}?mode=ro", uri=True)
        except sqlite3.Error as exc:
            self._logger.error("Failed to open copied notification DB: %s", exc)
            temp_copy.unlink(missing_ok=True)
            return

        try:
            cursor = connection.cursor()
            rows = cursor.execute(
                "SELECT Id, AppId, PackageId, CreatedTime, Payload FROM Notification "
                "WHERE Payload IS NOT NULL AND Id > ? ORDER BY Id ASC",
                (self._last_notification_id,),
            ).fetchall()
        except sqlite3.Error as exc:
            self._logger.error("Failed to query notification DB: %s", exc)
            connection.close()
            temp_copy.unlink(missing_ok=True)
            return
        finally:
            connection.close()
            temp_copy.unlink(missing_ok=True)

        if not rows:
            return

        for row in rows:
            notification_id, app_id, package_id, created_time, payload = row
            self._last_notification_id = max(self._last_notification_id, notification_id or 0)

            if notification_id in self._known_ids:
                continue
            if self._config.app_ids and not self._matches_app_id(app_id, package_id):
                continue

            parsed = self._parse_payload(payload)
            if not parsed:
                continue

            source = self._friendly_name(app_id or package_id or "")
            timestamp = convert_filetime(created_time) if created_time else time.time()

            event = NotificationEvent(
                source=source,
                title=parsed["title"],
                message=parsed["message"],
                metadata={
                    "app_id": app_id,
                    "package_id": package_id,
                    "created_time": created_time,
                    "payload_hint": parsed.get("payload_hint"),
                    **parsed.get("metadata", {}),
                },
                timestamp=timestamp,
            )
            self._queue.put(event)
            self._known_ids.append(notification_id)

        if len(self._known_ids) > self._config.max_cache_size:
            self._known_ids = self._known_ids[-self._config.max_cache_size :]

    def _matches_app_id(self, app_id: Optional[str], package_id: Optional[str]) -> bool:
        """Return True if the notification matches the configured application filters."""
        haystacks = [app_id or "", package_id or ""]
        haystacks = [value.lower() for value in haystacks if value]
        if not haystacks:
            return False

        for needle in self._config.app_ids:
            needle_lower = needle.lower()
            if any(needle_lower in hay for hay in haystacks):
                return True
        return False

    def _parse_payload(self, payload) -> Optional[Dict[str, str]]:
        """Decode the XML payload and return title/message metadata."""
        if isinstance(payload, memoryview):
            payload = payload.tobytes()
        if isinstance(payload, bytes):
            try:
                text_payload = payload.decode("utf-16-le")
            except UnicodeDecodeError:
                text_payload = payload.decode("utf-8", errors="ignore")
        elif isinstance(payload, str):
            text_payload = payload
        else:
            return None

        try:
            root = ET.fromstring(text_payload)
        except ET.ParseError:
            return None

        texts = [
            (elem.text or "").strip()
            for elem in root.findall(".//{*}text")
            if (elem.text or "").strip()
        ]
        title = texts[0] if texts else "Notification"
        message = " | ".join(texts[1:]) if len(texts) > 1 else (texts[0] if texts else "")

        metadata: Dict[str, str] = {}
        binding = root.find(".//{*}binding")
        if binding is not None:
            for attr in ("arguments", "contentId", "launch"):
                value = binding.attrib.get(attr)
                if value:
                    metadata[attr] = value

        return {
            "title": title,
            "message": message or title,
            "metadata": metadata,
            "payload_hint": (text_payload[:256] + "...") if len(text_payload) > 256 else text_payload,
        }

    def _friendly_name(self, app_identifier: str) -> str:
        """Map Windows app identifiers to human-readable titles."""
        if not app_identifier:
            return "Windows Notification"

        lookup = self._config.title_overrides or {}
        for key, value in lookup.items():
            if key.lower() in app_identifier.lower():
                return value

        default_map = {
            "msteams": "Microsoft Teams",
            "microsoftteams": "Microsoft Teams",
            "teams": "Microsoft Teams",
            "office.outlook": "Outlook",
            "microsoft.office.outlook": "Outlook",
            "hxoutlook": "Outlook (UWP)",
        }

        for key, value in default_map.items():
            if key in app_identifier.lower():
                return value

        return app_identifier


def resolve_env_path(path_value: str) -> Path:
    """Resolve environment variables and expand user home markers."""
    expanded = Path(os.path.expandvars(path_value)).expanduser()
    if not expanded.is_absolute():
        expanded = Path.cwd() / expanded
    return expanded


def convert_filetime(filetime_value: Optional[int]) -> float:
    """Convert Windows FILETIME (100ns intervals since 1601-01-01) to Unix epoch seconds."""
    if not filetime_value:
        return time.time()
    # Guard against negative or nonsensical values
    if filetime_value < 0:
        return time.time()
    return (filetime_value / 10_000_000) - 11644473600
