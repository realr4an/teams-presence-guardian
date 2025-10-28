# Teams Activity Keeper

> **Status:** Alpha preview (core presence keeping, log monitors, tray UI, and settings GUI working).  
> **Last updated:** 2025-10-28. Microsoft Graph integration, ML model training, and packaged installers are still outstanding.

Teams Activity Keeper is a lightweight Windows tray companion that keeps Microsoft Teams presence online when you intentionally step away, while monitoring local signals for urgent activity. It is designed for realr4an with a focus on privacy, low resource usage, and extensibility.

## Features
- **Presence Keeper:** Uses Windows power APIs (no input emulation) to keep the system awake only when you are away and pauses automatically when you return.
- **Smart Monitoring:** Watches configurable local sources (Teams, Outlook, Windows logs) using watchdog and parses new events in real time.
- **Scoring Engine:** Deterministic heuristics score each event with optional hooks for a logistic regression/XGBoost model.
- **Alert Escalation:** Toast + sound by default, with optional Telegram, Pushover, or Twilio escalation that honor quiet hours.
- **Tray UI:** Pystray-based icon with quick mode switches (Pause, Silent, Notify-only, Presence+Notify) and a presence toggle.
- **Settings GUI:** Tkinter editor (`settings_ui.py`) covering every configuration block so users can change settings without editing YAML.
- **Feedback Loop:** Records user feedback for future ML tuning and logs every action with timestamps.

## Project Structure
```
src/
  main.py             # Application entry point and orchestrator
  presence.py         # Windows presence keeper logic
  notifier.py         # Notification routing and escalation
  scorer.py           # Heuristic + optional ML scoring
  tray.py             # Tray icon controller (pystray)
  settings_ui.py      # Standalone configuration editor GUI
  config.yaml         # Example configuration (copy and edit)
models/
  (optional classifier.pkl lives here when trained)
logs/
  (runtime logs written here; git ignored)
requirements.txt
build_instructions.txt
README.md
```

## Getting Started
1. **Create a virtual environment (Python 3.11+):**
   ```powershell
   py -3.11 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
2. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```
3. **Configure:** Copy `src/config.yaml` somewhere writable if needed and adjust:
   - `presence` timings and behaviour
   - `scoring.vip_list`, `scoring.keywords`, quiet hours, optional ML model path
   - Notification channels (Telegram, Pushover, Twilio)
   - `monitors` pointing at Teams/Outlook log files or other local feeds
4. **Run the tray app:**
   ```powershell
   python .\src\main.py --config .\src\config.yaml
   ```
   A tray icon titled "Teams Activity Keeper" will appear; right-click to change modes or exit.

## Settings GUI
- Launch directly: `python .\src\settings_ui.py --config .\src\config.yaml`
- Or open it from the tray menu via **View Settings**.  
The GUI exposes every configuration value, supports CSV/log file selection, and writes updates back to the YAML file.

## Configuration Notes
- **Monitors:** Supports `text` (plain line) and `json` (line-delimited JSON) parsers. Add multiple monitors for Teams activity, Outlook logs, or custom sources.
- **Quiet Hours:** Enable in `scoring.quiet_hours`. Quiet hours apply a scoring penalty and can suppress notifications when `notifications.respect_quiet_hours` is true.
- **Feedback:** Enable `feedback.auto_log` to automatically flag delivered alerts as important, or capture manual feedback later using `NotificationManager.record_feedback`.
- **Security:** No network calls occur unless a channel is explicitly marked `enabled` and provided with credentials.

## Packaging Into an EXE
`build_instructions.txt` walks through creating:
1. `TeamsActivityKeeper.exe` - the background tray application (`--windowed --onefile` PyInstaller build).
2. Optionally, `TeamsActivityKeeperSettings.exe` - a separate launcher for `settings_ui.py` so the GUI remains accessible after packaging.

Remember to copy a writable `config.yaml` alongside the executables or embed a tailored one via `--add-data`.

## Logs & Feedback
- Runtime logs live in `logs/teams_activity_keeper.log` (ignored by git).
- Feedback data (if enabled) persists to `logs/feedback.csv`. Inspect these files to debug monitors, scoring, or notification routing.

## Future Improvements
1. Integrate Microsoft Graph presence and notification webhooks for richer context.
2. Bundle a feedback review UI and direct "important / not important" buttons.
3. Expand parsers for Windows notification archives and Teams SQLite caches.
4. Ship a reference ML model plus a training notebook.
5. Provide policy templates (quiet hours, DND) and automated installer scripts.

## Privacy
Teams Activity Keeper operates locally by default. Remote notifications only activate when you supply credentials, and those values stay inside your configuration file.
