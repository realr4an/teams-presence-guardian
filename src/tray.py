"""System tray integration for the Teams Activity Keeper application."""

from __future__ import annotations

import logging
import threading
from enum import Enum, auto
from typing import Callable, Optional

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:  # pragma: no cover - optional dependency
    pystray = None  # type: ignore
    Image = ImageDraw = None  # type: ignore


class AppMode(Enum):
    """Available operating modes exposed through the tray icon."""

    PAUSED = auto()
    SILENT = auto()
    NOTIFY_ONLY = auto()
    PRESENCE_NOTIFY = auto()


class TrayController:
    """Manages the tray icon, menu, and callbacks for user actions."""

    def __init__(
        self,
        on_mode_change: Callable[[AppMode], None],
        on_toggle_presence: Callable[[bool], None],
        on_quit: Callable[[], None],
        on_open_settings: Optional[Callable[[], None]] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._on_mode_change = on_mode_change
        self._on_toggle_presence = on_toggle_presence
        self._on_quit = on_quit
        self._on_open_settings = on_open_settings
        self._logger = logger or logging.getLogger(__name__)
        self._icon: Optional["pystray.Icon"] = None
        self._mode = AppMode.PRESENCE_NOTIFY
        self._presence_enabled = True
        self._tooltip_text = "Starting..."

    def start(self) -> None:
        """Create and run the tray icon in a background thread."""
        if pystray is None or Image is None:
            self._logger.warning("pystray/Pillow not installed; tray icon disabled.")
            return

        image = self._create_icon()
        menu = pystray.Menu(
            pystray.MenuItem(
                "Presence + Notify",
                lambda: self._set_mode(AppMode.PRESENCE_NOTIFY),
                checked=lambda item: self._mode is AppMode.PRESENCE_NOTIFY,
            ),
            pystray.MenuItem(
                "Notify-only Mode",
                lambda: self._set_mode(AppMode.NOTIFY_ONLY),
                checked=lambda item: self._mode is AppMode.NOTIFY_ONLY,
            ),
            pystray.MenuItem(
                "Silent Mode",
                lambda: self._set_mode(AppMode.SILENT),
                checked=lambda item: self._mode is AppMode.SILENT,
            ),
            pystray.MenuItem(
                "Pause",
                lambda: self._set_mode(AppMode.PAUSED),
                checked=lambda item: self._mode is AppMode.PAUSED,
            ),
            pystray.MenuItem(
                lambda item: "Presence Keeper: On" if self._presence_enabled else "Presence Keeper: Off",
                lambda: self._toggle_presence(),
            ),
            pystray.MenuItem(
                "View Settings",
                lambda: self._open_settings(),
                enabled=lambda _: self._on_open_settings is not None,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", lambda: self._quit()),
        )

        self._icon = pystray.Icon("Teams Activity Keeper", image, self._tooltip_text, menu)
        thread = threading.Thread(target=self._icon.run, name="TrayIcon", daemon=True)
        thread.start()
        self._logger.info("Tray icon started.")

    def update_tooltip(self, text: str) -> None:
        """Update the tooltip displayed when hovering over the tray icon."""
        self._tooltip_text = text
        if self._icon:
            self._icon.title = text

    def shutdown(self) -> None:
        """Stop the tray icon."""
        if self._icon:
            self._icon.stop()
            self._logger.info("Tray icon stopped.")

    def _set_mode(self, mode: AppMode) -> None:
        """Handle menu selection for mode changes."""
        self._mode = mode
        self._logger.info("Tray mode changed to %s.", mode.name)
        self._on_mode_change(mode)

    def _toggle_presence(self) -> None:
        """Allow the user to toggle presence keeping independently."""
        self._presence_enabled = not self._presence_enabled
        self._logger.info("Presence toggle requested: %s.", self._presence_enabled)
        self._on_toggle_presence(self._presence_enabled)

    def _quit(self) -> None:
        """Quit callback invoked from the tray menu."""
        self._logger.info("Quit selected from tray menu.")
        self._on_quit()
        if self._icon:
            self._icon.stop()

    def _open_settings(self) -> None:
        """Invoke settings GUI if handler provided."""
        if not self._on_open_settings:
            self._logger.warning("Settings callback not configured.")
            return
        self._logger.info("Opening settings GUI.")
        self._on_open_settings()

    def _create_icon(self) -> "Image.Image":
        """Generate a small branded icon for the tray menu."""
        size = (64, 64)
        image = Image.new("RGB", size, color="#1E1E2F")
        draw = ImageDraw.Draw(image)
        draw.ellipse((8, 8, 56, 56), outline="#5B8DEF", width=4)
        draw.text((18, 22), "R4", fill="#FFFFFF")
        return image
