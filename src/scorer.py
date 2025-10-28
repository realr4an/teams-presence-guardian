"""Rule-based and optional ML scoring for Teams Activity Keeper."""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

try:
    import joblib
except ImportError:  # pragma: no cover - optional until ML enabled
    joblib = None  # type: ignore

from notifier import NotificationEvent


@dataclass
class QuietHoursConfig:
    """Represents quiet hours window."""

    start: str = "22:00"
    end: str = "07:00"
    enabled: bool = False


@dataclass
class ScorerConfig:
    """Configuration for heuristic and ML scoring."""

    vip_list: Sequence[str] = field(default_factory=list)
    keywords: Sequence[str] = field(default_factory=lambda: ["urgent", "critical", "blocker"])
    quiet_hours: QuietHoursConfig = field(default_factory=QuietHoursConfig)
    base_threshold: float = 4.0
    tier2_threshold: float = 6.0
    tier3_threshold: float = 10.0
    ml_model_path: Optional[str] = None


@dataclass
class ScoreResult:
    """Scoring output with explanations."""

    score: float
    reasons: List[str]
    quiet_hours_active: bool


class EventScorer:
    """Combines deterministic heuristics with an optional ML model."""

    MENTION_BONUS = 5
    VIP_BONUS = 3
    KEYWORD_BONUS = 2
    QUIET_HOURS_PENALTY = -3

    def __init__(self, config: ScorerConfig, logger: Optional[logging.Logger] = None) -> None:
        self._config = config
        self._logger = logger or logging.getLogger(__name__)
        self._model = self._load_model(Path(config.ml_model_path)) if config.ml_model_path else None
        self._keyword_patterns = [
            (re.compile(rf"\b{re.escape(word)}\b", re.IGNORECASE), word) for word in config.keywords
        ]
        self._logger.debug("EventScorer initialized with config: %s", self._config)

    def score(self, event: NotificationEvent) -> ScoreResult:
        """Score an event and return the numeric score with rationale."""
        score = 0.0
        reasons: List[str] = []

        message = f"{event.title} {event.message}".lower()
        metadata = event.metadata or {}

        if metadata.get("mentioned") or "@" in event.message:
            score += self.MENTION_BONUS
            reasons.append("+5 mention detected")

        sender = metadata.get("sender", "")
        if sender and sender.lower() in {vip.lower() for vip in self._config.vip_list}:
            score += self.VIP_BONUS
            reasons.append(f"+3 VIP sender: {sender}")

        for pattern, keyword in self._keyword_patterns:
            if pattern.search(message):
                score += self.KEYWORD_BONUS
                reasons.append(f"+2 keyword match: {keyword}")
                break

        quiet_hours_active = self._is_quiet_hours()
        if quiet_hours_active:
            score += self.QUIET_HOURS_PENALTY
            reasons.append("-3 quiet hours penalty")

        if self._model:
            ml_score = self._score_with_model(event)
            if ml_score is not None:
                score += ml_score
                reasons.append(f"+{ml_score:.1f} ML adjustment")

        self._logger.debug(
            "Event scored: id=%s score=%.1f reasons=%s quiet_hours=%s",
            event.event_id,
            score,
            reasons,
            quiet_hours_active,
        )
        return ScoreResult(score=score, reasons=reasons, quiet_hours_active=quiet_hours_active)

    def _load_model(self, path: Path):
        """Load a pre-trained model using joblib when available."""
        if not path.exists():
            self._logger.warning("ML model path %s does not exist; running heuristic-only.", path)
            return None
        if joblib is None:
            self._logger.error("joblib not installed; cannot load ML model.")
            return None
        try:
            model = joblib.load(path)
            self._logger.info("ML model loaded from %s.", path)
            return model
        except Exception as exc:  # pragma: no cover
            self._logger.error("Failed to load ML model: %s", exc)
            return None

    def _score_with_model(self, event: NotificationEvent) -> Optional[float]:
        """Generate an adjustment score using the optional ML model."""
        if not self._model:
            return None

        sender = event.metadata.get("sender", "")
        features = [
            float("@" in event.message),
            len(event.message),
            sum(1 for pattern, _ in self._keyword_patterns if pattern.search(event.message)),
            1.0 if sender and sender.lower() in {vip.lower() for vip in self._config.vip_list} else 0.0,
        ]

        try:
            proba = self._model.predict_proba([features])[0][1]
            adjustment = (proba * 4) - 2  # map probability into [-2, +2]
            return adjustment
        except Exception as exc:  # pragma: no cover
            self._logger.error("ML scoring failed: %s", exc)
            return None

    def _is_quiet_hours(self) -> bool:
        """Return True when quiet hours are enabled and currently active."""
        cfg = self._config.quiet_hours
        if not cfg.enabled:
            return False

        now_struct = time.localtime()
        current_minutes = now_struct.tm_hour * 60 + now_struct.tm_min
        start_minutes = _parse_hhmm(cfg.start)
        end_minutes = _parse_hhmm(cfg.end)

        if start_minutes <= end_minutes:
            return start_minutes <= current_minutes < end_minutes
        return current_minutes >= start_minutes or current_minutes < end_minutes


def _parse_hhmm(value: str) -> int:
    """Convert an HH:MM string to minutes."""
    try:
        hours, minutes = value.split(":")
        return int(hours) * 60 + int(minutes)
    except ValueError:
        raise ValueError(f"Invalid HH:MM format: {value}") from None
