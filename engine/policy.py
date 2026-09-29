#!/usr/bin/env python3
import random
from typing import List, Optional, Tuple

from classify import HOSTILE

ROTATION = ["moodle", "registry", "finance", "research"]


class SwitchPolicy:
    def __init__(self, dwell: float = 45.0, quiet_settle: float = 600.0,
                 default_persona: str = "moodle"):
        self.dwell = dwell
        self.quiet_settle = quiet_settle
        self.default = default_persona
        self.current = default_persona
        self.last_switch = 0.0
        self.last_hostile = 0.0
        self.hot = False
        self.pending_target: Optional[str] = None
        self.pending_reason: str = ""
        self._rng = random.Random()

    def _random_persona(self) -> str:
        others = [p for p in ROTATION if p != self.current]
        return self._rng.choice(others) if others else self.default

    def decide(self,
               classifications: List[Tuple[str, str, float, bool]],
               now: float,
               current: str) -> Tuple[Optional[str], str, bool]:
        """classifications: (ip, label, confidence, active)."""
        self.current = current

        all_labels = [label for _, label, _, _ in classifications]
        hostile_labels = [l for l in all_labels if l in HOSTILE]
        self.hot = bool(hostile_labels)

        if self.hot:
            self.last_hostile = now

        any_active = any(active for _, _, _, active in classifications)

        def clear_pending() -> None:
            self.pending_target = None
            self.pending_reason = ""

        if now - self.last_switch < self.dwell:
            clear_pending()
            return None, f"within dwell ({self.dwell:.0f}s)", self.hot

        # Section 10 policy table: check in order of priority.
        if "active_backend_testing" in all_labels:
            clear_pending()
            return None, "hold (active_backend_testing)", self.hot

        if "indexing" in all_labels:
            reason: Optional[str] = "indexing traffic present"
        elif "broad_scanning" in all_labels:
            reason = "broad scanning detected"
        else:
            reason = None

        if reason is not None:
            target = self._random_persona()
            if target == current:
                clear_pending()
                return None, "rotation would repeat persona", self.hot
            # Target and reason are re-derived together each tick; applied only when nothing is active.
            self.pending_target, self.pending_reason = target, reason
            if any_active:
                return None, f"rotation to {target} queued (session active)", self.hot
            clear_pending()
            return target, reason, self.hot

        clear_pending()

        if current != self.default and now - self.last_hostile >= self.quiet_settle:
            return self.default, "quiet period; restoring default", self.hot

        return None, "calm", self.hot
