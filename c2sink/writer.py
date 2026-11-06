"""Durable, bounded event writer.

The capture hot path must not block on disk I/O and must not silently lose
events. `EventWriter` takes serialised event lines on a bounded queue that a
background thread drains to an append-only JSONL file. Its contract:

- **Non-blocking submit.** `submit()` never blocks the caller; if the queue is
  full (traffic outpacing the disk) it drops the event and increments a counter,
  so backpressure is *visible*, never hidden.
- **Survives write errors.** A failed write (e.g. the disk filled up) is counted
  and the writer keeps running rather than taking the collector down.
- **Defined flush/shutdown.** The file is flushed on a cadence and on `close()`,
  which drains whatever is still queued before closing. `fsync=True` forces each
  flush to stable storage.
- **Crash tolerance.** Append-only JSONL means a crash can leave at most a
  partial final line; `report.load_events` skips an unparseable line rather than
  failing, so the reporting side tolerates a half-written log.
"""

from __future__ import annotations

import os
import queue
import threading
import time

from .metrics import Metrics


class EventWriter:
    def __init__(self, path: str, metrics: Metrics = None, max_queue: int = 10000,
                 flush_interval: float = 1.0, fsync: bool = False):
        self.path = path
        self.metrics = metrics or Metrics()
        self.flush_interval = flush_interval
        self.fsync = fsync
        self._q: "queue.Queue[str]" = queue.Queue(maxsize=max_queue)
        self._stop = threading.Event()
        self._fh = open(path, "a", buffering=1, encoding="utf-8")
        try:
            os.chmod(path, 0o600)            # the log holds subscriber metadata
        except OSError:
            pass
        self._thread = threading.Thread(target=self._run, name="c2sink-writer", daemon=True)
        self._thread.start()

    def submit(self, line: str) -> bool:
        """Non-blocking. Returns False and counts a drop if the queue is full."""
        try:
            self._q.put_nowait(line)
            self.metrics.queue_depth = self._q.qsize()
            return True
        except queue.Full:
            self.metrics.events_dropped += 1
            return False

    def submit_event(self, ev) -> bool:
        return self.submit(ev.to_json_line())

    def _run(self) -> None:
        last_flush = time.time()
        while not (self._stop.is_set() and self._q.empty()):
            try:
                line = self._q.get(timeout=0.2)
            except queue.Empty:
                line = None
            if line is not None:
                self._write(line)
                self._q.task_done()
            now = time.time()
            if now - last_flush >= self.flush_interval:
                self._flush()
                last_flush = now
            self.metrics.queue_depth = self._q.qsize()

    def _write(self, line: str) -> None:
        try:
            n = self._fh.write(line + "\n")
            self.metrics.events_written += 1
            self.metrics.bytes_written += n
        except OSError:
            self.metrics.write_errors += 1   # e.g. ENOSPC: count and keep running

    def _flush(self) -> None:
        try:
            self._fh.flush()
            if self.fsync:
                os.fsync(self._fh.fileno())
        except OSError:
            self.metrics.write_errors += 1

    def close(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._thread.join(timeout=timeout)
        while True:                          # drain anything the thread missed
            try:
                self._write(self._q.get_nowait())
            except queue.Empty:
                break
        self._flush()
        try:
            self._fh.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
