"""Utility class to display an ephemeral progress bar in stdout
This is a private strongarm module.
"""

import sys
import time
import threading
from typing import Optional


class ConsoleProgressBar:
    def set_progress(self, progress: float) -> None:
        """Expects a value between 0 and 1
        """
        self.progress = progress

    def __init__(self, prefix: str = None, bar_width=40, update_interval=0.5):
        self.update_interval = update_interval
        self.bar_width = bar_width
        self.progress = 0
        self.prefix = ''
        if prefix:
            self.prefix = f'{prefix}\t'
        self._in_context_manager = False
        self.start_time: Optional[float] = None

    def _update_bar(self):
        while self._in_context_manager:
            elapsed_seconds = time.time() - self.start_time
            elapsed_time = f'{(elapsed_seconds // 60) % 60:02.0f}:{elapsed_seconds % 60:02.0f}'

            complete_segment = '#' * int(self.progress * self.bar_width)
            incomplete_segment = '=' * int((1 - self.progress) * self.bar_width)
            progress_str = f'[{complete_segment}|{incomplete_segment}]'
            progress_str = f'{self.prefix}{elapsed_time}\t\t{int(self.progress*100)}%\t{progress_str}'

            # Write the progress bar, wait, and delete it from stdout
            sys.stdout.write(progress_str)
            sys.stdout.flush()
            time.sleep(self.update_interval)
            sys.stdout.write('\b' * len(progress_str))
            sys.stdout.flush()

    def __enter__(self):
        self._in_context_manager = True
        self.start_time = time.time()
        threading.Thread(target=self._update_bar).start()
        return self

    def __exit__(self, exception, value, tb):
        self._in_context_manager = False
        time.sleep(self.update_interval)
        if exception is not None:
            return False
