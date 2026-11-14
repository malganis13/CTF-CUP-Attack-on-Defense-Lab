"""Общий бюджет исходящих запросов.

Один токен-бакет на процесс. Проба списывает токены до первого запроса:
если бюджета нет — проба не начинается, а не «немного идёт». Это защита от
случайного флуда повторными нажатиями и от того, чтобы инструмент вообще
можно было принять за генератор нагрузки.

Числа выбраны так, чтобы нагрузка была заведомо ниже любой мыслимой границы:
30 запросов за 60 секунд на весь процесс — это 0.5 запроса в секунду.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class Budget:
    capacity: int = 30
    window: float = 60.0
    _stamps: deque = field(default_factory=deque, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def _trim(self, now: float) -> None:
        while self._stamps and self._stamps[0] <= now - self.window:
            self._stamps.popleft()

    def take(self, count: int) -> tuple[bool, float]:
        """Списать count запросов. Возвращает (разрешено, секунд до повтора)."""
        if count <= 0:
            return True, 0.0
        with self._lock:
            now = time.monotonic()
            self._trim(now)
            if len(self._stamps) + count > self.capacity:
                if not self._stamps:
                    return False, self.window
                retry = max(0.0, self._stamps[0] + self.window - now)
                return False, retry
            for _ in range(count):
                self._stamps.append(now)
            return True, 0.0

    def peek(self) -> dict:
        with self._lock:
            now = time.monotonic()
            self._trim(now)
            return {
                "capacity": self.capacity,
                "window": self.window,
                "used": len(self._stamps),
                "remaining": max(0, self.capacity - len(self._stamps)),
            }


BUDGET = Budget()
