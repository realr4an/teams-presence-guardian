"""Notification routing and escalation logic for Teams Activity Keeper."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from win10toast import ToastNotifier
except ImportError:  # pragma: no cover - optional dependency at runtime
    ToastNotifier = None  # type: ignore

try:
    import winsound
except ImportError:  # pragma: no cover - optional on non-Windows systems
    winsound = None  # type: ignore

try:
    import requests
except ImportError:  # pragma: no cover - optional if APIs disabled
    requests = None  # type: ignore


class AlertLevel(Enum):
    """The escalation tier for notifications."""

    TIER1 = auto()
    TIER2 = auto()
    TIER3 = auto()


@dataclass
class NotificationEvent:
    """Represents a parsed event that might trigger user-facing alerts."""

    source: str
    title: str
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    score: float = 0.0
    reasons: List[str] = field(default_factory=list)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)


@dataclass
class NotificationManagerConfig:
    """Configuration for the notification manager component."""

    toast_enabled: bool = True
    repeat_minutes: int = 5
    sound_enabled: bool = True
    sound_file: Optional[str] = None
    telegram: Dict[str, Any] = field(default_factory=dict)
    pushover: Dict[str, Any] = field(default_factory=dict)
    twilio: Dict[str, Any] = field(default_factory=dict)
    quiet_hours_enabled: bool = False
    tier2_threshold: float = 6.0
    tier3_threshold: float = 10.0


class NotificationManager:
    """Dispatches notifications to local and remote channels with escalation."""

    def __init__(
        self,
        config: NotificationManagerConfig,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._config = config
        self._logger = logger or logging.getLogger(__name__)
        self._toast = ToastNotifier() if ToastNotifier and self._config.toast_enabled else None
        self._last_alerts: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._logger.debug("NotificationManager initialized with config: %s", self._config)

    def handle(self, event: NotificationEvent, quiet_hours_active: bool) -> None:
        """Route a notification event using the configured escalation rules."""
        if quiet_hours_active and self._config.quiet_hours_enabled:
            self._logger.info(
                "Quiet hours active; suppressing alert for %s (score=%.1f).",
                event.event_id,
                event.score,
            )
            return

        alert_level = self._determine_level(event.score)
        self._logger.info(
            "Dispatching alert %s (%s) score=%.1f reasons=%s",
            event.event_id,
            alert_level.name,
            event.score,
            event.reasons,
        )

        self._record_alert(event)

        if alert_level in (AlertLevel.TIER1, AlertLevel.TIER2, AlertLevel.TIER3):
            self._send_toast(event)
            self._play_sound()

        if alert_level in (AlertLevel.TIER2, AlertLevel.TIER3):
            self._trigger_push(event)

        if alert_level is AlertLevel.TIER3:
            self._trigger_escalation(event)

    def record_feedback(self, event_id: str, was_important: bool, storage_path: Path) -> None:
        """Persist user feedback to help with later ML fine-tuning."""
        storage_path.parent.mkdir(parents=True, exist_ok=True)
        line = f"{time.time():.0f},{event_id},{int(was_important)}\n"
        with storage_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        self._logger.info("Feedback recorded for %s (important=%s).", event_id, was_important)

    def _record_alert(self, event: NotificationEvent) -> None:
        """Remember when an alert was last sent to apply repeat throttling."""
        with self._lock:
            self._last_alerts[event.event_id] = time.time()

    def should_repeat(self, event_id: str) -> bool:
        """Return True if enough time has elapsed to repeat the alert."""
        minutes = max(self._config.repeat_minutes, 1)
        with self._lock:
            last = self._last_alerts.get(event_id, 0)
        return (time.time() - last) >= minutes * 60

    def _determine_level(self, score: float) -> AlertLevel:
        """Translate a numeric score into an escalation tier."""
        if score >= self._config.tier3_threshold:
            return AlertLevel.TIER3
        if score >= self._config.tier2_threshold:
            return AlertLevel.TIER2
        return AlertLevel.TIER1

    def _send_toast(self, event: NotificationEvent) -> None:
        """Display a local toast notification when possible."""
        if not self._toast:
            self._logger.warning("win10toast not available; skipping toast for %s.", event.event_id)
            return

        duration = 10
        message = f"{event.title}\n{event.message}"
        self._toast.show_toast(
            f"[Teams Activity Keeper] {event.source}",
            message,
            duration=duration,
            threaded=True,
        )
        self._logger.debug("Toast notification issued for %s.", event.event_id)

    def _play_sound(self) -> None:
        """Play a simple reminder sound where supported."""
        if not self._config.sound_enabled or winsound is None:
            return

        if self._config.sound_file:
            try:
                winsound.PlaySound(self._config.sound_file, winsound.SND_FILENAME | winsound.SND_ASYNC)
            except RuntimeError as exc:
                self._logger.error("Failed to play custom sound: %s", exc)
        else:
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)

    def _trigger_push(self, event: NotificationEvent) -> None:
        """Send tier-2 alerts to remote push channels when configured."""
        if requests is None:
            self._logger.debug("requests not installed; skipping push notification.")
            return

        if self._config.telegram.get("enabled"):
            self._send_telegram(event)

        if self._config.pushover.get("enabled"):
            self._send_pushover(event)

    def _trigger_escalation(self, event: NotificationEvent) -> None:
        """Escalate tier-3 alerts via Twilio or desktop wake-ups."""
        if self._config.twilio.get("enabled"):
            self._send_twilio_call(event)
        else:
            self._logger.info("Tier-3 escalation triggered without Twilio; consider enabling it.")

    def _send_telegram(self, event: NotificationEvent) -> None:
        """Send a Telegram message via bot API."""
        bot_token = self._config.telegram.get("bot_token")
        chat_id = self._config.telegram.get("chat_id")
        if not bot_token or not chat_id:
            self._logger.error("Telegram enabled but bot_token/chat_id missing.")
            return
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": f"[Teams Activity Keeper]\n{event.title}\n{event.message}",
        }
        try:
            response = requests.post(url, json=payload, timeout=5)
            response.raise_for_status()
            self._logger.info("Telegram alert sent for %s.", event.event_id)
        except Exception as exc:  # pragma: no cover - best effort networking
            self._logger.error("Telegram alert failed: %s", exc)

    def _send_pushover(self, event: NotificationEvent) -> None:
        """Send a Pushover push notification."""
        token = self._config.pushover.get("api_token")
        user_key = self._config.pushover.get("user_key")
        if not token or not user_key:
            self._logger.error("Pushover enabled but credentials missing.")
            return
        url = "https://api.pushover.net/1/messages.json"
        payload = {
            "token": token,
            "user": user_key,
            "title": "Teams Activity Keeper",
            "message": f"{event.title}\n{event.message}",
        }
        try:
            response = requests.post(url, data=payload, timeout=5)
            response.raise_for_status()
            self._logger.info("Pushover alert sent for %s.", event.event_id)
        except Exception as exc:  # pragma: no cover
            self._logger.error("Pushover alert failed: %s", exc)

    def _send_twilio_call(self, event: NotificationEvent) -> None:
        """Trigger a phone call via Twilio for highest priority events."""
        account_sid = self._config.twilio.get("account_sid")
        auth_token = self._config.twilio.get("auth_token")
        from_number = self._config.twilio.get("from_number")
        to_number = self._config.twilio.get("to_number")
        if not all([account_sid, auth_token, from_number, to_number]):
            self._logger.error("Twilio enabled but credentials missing.")
            return

        if requests is None:
            self._logger.error("requests not installed; cannot invoke Twilio API.")
            return

        url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Calls.json"
        payload = {
            "To": to_number,
            "From": from_number,
            "Twiml": f"<Response><Say>{event.message}</Say></Response>",
        }
        try:
            response = requests.post(url, data=payload, auth=(account_sid, auth_token), timeout=5)
            response.raise_for_status()
            self._logger.info("Twilio call initiated for %s.", event.event_id)
        except Exception as exc:  # pragma: no cover
            self._logger.error("Twilio call failed: %s", exc)

