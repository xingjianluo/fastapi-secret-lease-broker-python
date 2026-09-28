"""可注入时钟，便于测试过期与轮换窗口。"""

from __future__ import annotations

import time
from typing import Callable

Clock = Callable[[], float]


def system_clock() -> float:
    return time.time()
