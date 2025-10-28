"""Helpers for managing Windows presence without input emulation."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

try:
    import ctypes
except ImportError:  # pragma: no cover - shipped on Windows
    ctypes = None  # type: ignore


# Windows execution state flags
ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ES_DISPLAY_REQUIRED = 0x00000002


class PresenceKeeperError(RuntimeError):
    """Raised when the presence keeper cannot interact with Windows APIs."""


@dataclass
class PresenceConfig:
    """Configuration values controlling the presence keeper thread."""

    keepalive_interval_seconds: int = 45
    allow_display_sleep: bool = False
    idle_timeout_seconds: int = 300
    resume_grace_period_seconds: int = 15


@dataclass
class PresenceState:
    """Tracks the internal state of the presence keeper."""

    active: bool = True
    paused: bool = False
    last_user_interaction: float = field(default_factory=time.time)


class PresenceKeeper:
    """Maintains the user's online presence by preventing Windows idle state."""

    def __init__(self, config: PresenceConfig, logger: Optional[logging.Logger] = None) -> None:
        self._config = config
        self._logger = logger or logging.getLogger(__name__)
        self._state = PresenceState()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        if ctypes is None or not hasattr(ctypes, "windll"):
            raise PresenceKeeperError("ctypes.windll is required on Windows hosts.")

        self._kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        self._logger.debug("PresenceKeeper initialized with config: %s", self._config)

    @property
    def state(self) -> PresenceState:
        """Return a snapshot of the current presence state."""
        return self._state

    def start(self) -> None:
        """Start the background thread if it is not running already."""
        if self._thread and self._thread.is_alive():
            self._logger.debug("PresenceKeeper thread already running.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="PresenceKeeper", daemon=True)
        self._thread.start()
        self._logger.info("PresenceKeeper thread started.")

    def stop(self) -> None:
        """Stop the background thread gracefully."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._config.keepalive_interval_seconds * 2)
        self._logger.info("PresenceKeeper thread stopped.")

    def pause(self) -> None:
        """Pause keep-alive signals until resumed."""
        self._state.paused = True
        self._logger.info("PresenceKeeper paused.")

    def resume(self) -> None:
        """Resume keep-alive signals."""
        self._state.paused = False
        self._state.last_user_interaction = time.time()
        self._logger.info("PresenceKeeper resumed.")

    def notify_user_activity(self) -> None:
        """Record a user interaction to allow a short grace period."""
        self._state.last_user_interaction = time.time()
        self._logger.debug("User activity recorded at %s", self._state.last_user_interaction)

    def set_active(self, active: bool) -> None:
        """Enable or disable the presence keeper entirely."""
        if self._state.active == active:
            return
        self._state.active = active
        self._logger.info("PresenceKeeper active state set to %s", active)

    def _run(self) -> None:
        """Background loop calling into SetThreadExecutionState."""
        interval = max(15, self._config.keepalive_interval_seconds)
        while not self._stop_event.is_set():
            now = time.time()
            idle_seconds = now - self._state.last_user_interaction

            if self._state.active and not self._state.paused:
                if idle_seconds >= self._config.resume_grace_period_seconds:
                    self._send_keepalive()
                else:
                    self._logger.debug(
                        "Within grace period (%.1fs < %ss); skipping keepalive.",
                        idle_seconds,
                        self._config.resume_grace_period_seconds,
                    )
            else:
                self._logger.debug(
                    "PresenceKeeper inactive (active=%s paused=%s).",
                    self._state.active,
                    self._state.paused,
                )

            self._stop_event.wait(interval)

    def _send_keepalive(self) -> None:
        """Invoke the Windows API to prevent sleep/idle behaviour."""
        flags = ES_CONTINUOUS | ES_SYSTEM_REQUIRED
        if not self._config.allow_display_sleep:
            flags |= ES_DISPLAY_REQUIRED

        result = self._kernel32.SetThreadExecutionState(flags)
        if result == 0:
            self._logger.error("SetThreadExecutionState failed (returned 0).")
            raise PresenceKeeperError("Failed to request execution state from Windows.")

        self._logger.debug("SetThreadExecutionState invoked with flags=0x%X", flags)
