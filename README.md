# Teams Activity Keeper

> **Status:** Alpha preview (core presence keeping, log monitors, tray UI, and settings GUI working).  
> **Last updated:** 2025-10-28. Microsoft Graph integration, ML model training, and packaged installers are still outstanding.

Teams Activity Keeper is a lightweight Windows tray companion that keeps Microsoft Teams presence online when you intentionally step away, while monitoring local signals for urgent activity. The project focuses on privacy, low resource usage, and extensibility.

## Features
- **Presence Keeper:** Uses Windows power APIs (no input emulation) to keep the system awake only when you are away and pauses automatically when you return.
- **Smart Monitoring:** Tails real Teams log files (classic + new) or any custom feed via watchdog and scores new entries immediately.
- **Action Center Watcher:** Polls the Windows notifications database to capture toast alerts from Teams, Outlook, and other apps without extra APIs.
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
   - `monitors` entries for Teams logs (classic + new) or add your own feeds
   - `windows_notifications` if you want to listen to Action Center toasts (Teams/Outlook, etc.)
   - Secrets can reference environment variables via `${MY_ENV_VAR}` tokens so you avoid storing credentials in plain text.
4. **Run the tray app:**
   ```powershell
   python .\src\main.py --config .\src\config.yaml
   ```
   A tray icon titled "Teams Activity Keeper" will appear; right-click to change modes or exit.

### Quick Alert Test
Before relying on remote channels, trigger a synthetic alert:
```powershell
python .\src\main.py --config .\src\config.yaml --send-test-alert --test-alert-message "Hello from TAK"
```
This sends a tier-3 notification through every enabled channel (toast, sound, Telegram, Pushover, Twilio). Adjust `--test-alert-title` / `--test-alert-message` as needed.

## Settings GUI
- Launch directly: `python .\src\settings_ui.py --config .\src\config.yaml`
- Or open it from the tray menu via **View Settings**.  
The GUI exposes every configuration value, supports CSV/log file selection, and writes updates back to the YAML file.

## Configuration Notes
- **Monitors:** Supports `text`, `json`, and heuristics for Teams logs via `teams_legacy` / `teams_modern`. Add additional monitors for any append-only log file you rely on.
- **Windows notifications:** Enable `windows_notifications` to poll the Action Center SQLite database; adjust `app_ids` filters to match Teams/Outlook identifiers in your environment.
- **Secrets & environment variables:** The loader replaces `${ENV_VAR}` tokens with values from the current environment, so you can keep API keys out of source control.
- **Quiet Hours:** Enable in `scoring.quiet_hours`. Quiet hours apply a scoring penalty and can suppress notifications when `notifications.respect_quiet_hours` is true.
- **Feedback:** Enable `feedback.auto_log` to automatically flag delivered alerts as important, or capture manual feedback later using `NotificationManager.record_feedback`.
- **Security:** No network calls occur unless a channel is explicitly marked `enabled` and provided with credentials.

## Monitoring Real Sources
1. **Teams (classic):** Leave `monitors[0]` pointing to `%APPDATA%\Microsoft\Teams\logs.txt`. A new mention or chat message appends entries containing `notification`, which the heuristic parser converts into alerts.
2. **Teams (new):** If you use the new Teams client, ensure the second monitor path exists (`%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\logs.txt`). Adjust the parser to `text` if Microsoft changes the format.
3. **Windows Action Center:** Keep `windows_notifications.enabled = true` so toast notifications from Teams/Outlook become `NotificationEvent`s even when log formats drift. Run a quick test by sending yourself a Teams message and watching `logs/teams_activity_keeper.log` for the scored event.
4. **Custom sources:** Add more monitor entries (e.g., shared drive incident logs) with `parser: json` for JSONL feeds or `parser: text` for simple append-only files.

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
