"""Utility class to display an ephemeral progress bar in stdout
This is a private strongarm module.
"""

import sys
import threading
import time
from types import TracebackType
from typing import Optional


class ConsoleProgressBar:
    def set_progress(self, progress: float) -> None:
        """Expects a value between 0 and 1
        """
        self.progress = progress

    def __init__(
        self, prefix: str = None, bar_width: int = 40, update_interval: float = 0.5, enabled: bool = True
    ) -> None:
        self.prefix = ""
        if prefix:
            self.prefix = f"{prefix}\t"

        self.progress = 0
        self.bar_width = bar_width
        self.update_interval = update_interval

        self.start_time = 0.0
        self._in_context_manager = False
        self.enabled = enabled

    def _update_bar(self) -> None:
        while self._in_context_manager:
            if not self.enabled:
                time.sleep(self.update_interval)
                continue

            elapsed_seconds = time.time() - self.start_time
            elapsed_time = f"{(elapsed_seconds // 60) % 60:02.0f}:{elapsed_seconds % 60:02.0f}"

            complete_segment = "#" * int(self.progress * self.bar_width)
            incomplete_segment = "=" * int((1 - self.progress) * self.bar_width)
            progress_str = f"[{complete_segment}|{incomplete_segment}]"
            progress_str = f"{self.prefix}{elapsed_time}\t\t{int(self.progress*100)}%\t{progress_str}"

            # Write the progress bar, wait, and delete it from stdout
            sys.stdout.write(progress_str)
            sys.stdout.flush()
            time.sleep(self.update_interval)
            sys.stdout.write("\r")
            sys.stdout.flush()

    def __enter__(self) -> "ConsoleProgressBar":
        self._in_context_manager = True
        self.start_time = time.time()
        threading.Thread(target=self._update_bar).start()
        return self

    def __exit__(self, exc_type: Optional[BaseException], exc_val: Optional[Exception], exc_tb: TracebackType) -> None:
        self._in_context_manager = False
        time.sleep(self.update_interval)
