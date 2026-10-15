"""Presence on the mesh that follows what the verdict API is really doing.

Five events, five fixed labels, nothing else. A label is chosen from `EVENTS` by name; no subject
name, document text, evidence, verdict, amount or score can reach a heartbeat because the only thing a
caller can hand in is one of those five names.

    issuing a receipt            BUILDING     "Issuing a receipt"
    verifying                    TESTING      "Verifying"
    witnessing a log             REVIEWING    "Witnessing a log"
    a refused or broken chain    INCIDENT     "Chain refused or broken"   (shown longer than the others)
    nothing happening            IDLE

Rules it keeps:
- Inert unless FLASHYOS_ORG_ID, FLASHYOS_AGENT_TOKEN and FLASHYOS_AGENT_NAME are all set and valid:
  no thread, no socket, no state change.
- Never in the verdict's path: `note()` records an event and returns; a daemon worker thread does the
  sending. A slow, failing or hung FlashyOS cannot slow, fail or hang a verdict.
- Never a flood: heartbeats are spaced at least `min_gap` seconds apart, a burst of requests is
  one heartbeat, and a quiet server still sends one every `refresh` seconds so it stays visible.
- Never an exception: every failure is swallowed (the reporter itself never retries).
"""

from __future__ import annotations

import os
import threading
import time

from diligenceos.flashy import mesh_reporter

# event -> (status, task label). Statuses are mesh_reporter.STATUSES; labels are fixed text.
EVENTS = {
    "issuing": ("BUILDING", "Issuing a receipt"),
    "verifying": ("TESTING", "Verifying"),
    "witnessing": ("REVIEWING", "Witnessing a log"),
    "incident": ("INCIDENT", "Chain refused or broken"),
    "idle": ("IDLE", ""),
}
INCIDENT_HOLD_FACTOR = 8      # an incident stays visible this many times longer than ordinary activity


class Presence:
    def __init__(self, send=None, clock=time.monotonic, env=None, *, min_gap=2.0, refresh=60.0,
                 idle_after=15.0, tick=1.0, start_thread=True):
        self.env = os.environ if env is None else env
        self.clock = clock
        self.min_gap, self.refresh, self.idle_after, self.tick = min_gap, refresh, idle_after, tick
        self._send = send if send is not None else self._send_via_env
        self._start_thread = start_thread
        self.configured = bool(mesh_reporter.read_config(self.env)["configured"])
        self._lock = threading.Lock()
        self._wake_event = threading.Event()
        self._stop_event = threading.Event()
        self._thread = None
        self._want = "idle"
        self._last_activity = None
        self._sent = None            # the event last sent
        self._last_sent = None       # when
        self._seen_events = []       # what note() was given (for tests; bounded)

    # -- the only thing a caller can do ------------------------------------------------------------
    def note(self, event) -> None:
        """Record that something happened. Cheap, non-blocking, never raises."""
        try:
            if not self.configured or not isinstance(event, str) or event not in EVENTS:
                return
            with self._lock:
                self._want = event
                if event != "idle":
                    self._last_activity = self.clock()
                if len(self._seen_events) < 1000:
                    self._seen_events.append(event)
            self._wake()
        except Exception:  # noqa: BLE001 - presence must never break the product
            return

    # -- the scheduler (called by the worker thread; called directly by tests) ----------------------
    def step(self, now=None):
        """One scheduling decision. Returns the event sent, or None. Never raises."""
        try:
            if not self.configured:
                return None
            now = self.clock() if now is None else now
            with self._lock:
                want = self._want
                hold = self.idle_after * (INCIDENT_HOLD_FACTOR if want == "incident" else 1)
                if want != "idle" and self._last_activity is not None and now - self._last_activity > hold:
                    want = "idle"
                due = self._last_sent is None or now - self._last_sent >= self.refresh
                changed = want != self._sent
                if not (changed or due):
                    return None
                if self._last_sent is not None and now - self._last_sent < self.min_gap:
                    return None
                self._sent, self._last_sent = want, now   # recorded before sending: no retry storm on failure
            status, task = EVENTS[want]
            try:
                self._send(status, task)
            except Exception:  # noqa: BLE001
                pass
            return want
        except Exception:  # noqa: BLE001
            return None

    # -- worker thread -------------------------------------------------------------------------------
    def _wake(self):
        if self._start_thread and self._thread is None:
            self.start()
        self._wake_event.set()

    def start(self):
        """Start the worker (idempotent). Does nothing when unconfigured."""
        if not self.configured or self._thread is not None:
            return
        with self._lock:
            if self._thread is not None:
                return
            self._thread = threading.Thread(target=self._run, name="diligenceos-presence", daemon=True)
            self._thread.start()

    def stop(self):
        self._stop_event.set()
        self._wake_event.set()

    def _run(self):
        while not self._stop_event.is_set():
            self.step()
            self._wake_event.wait(self.tick)
            self._wake_event.clear()

    def _send_via_env(self, status, task):
        mesh_reporter.heartbeat(status, task, 0, env=self.env)


# -- module-level default, built from the real environment on first use -------------------------------
_default = None
_default_lock = threading.Lock()


def default():
    global _default
    with _default_lock:
        if _default is None:
            _default = Presence()
        return _default


def set_default(p):
    global _default
    with _default_lock:
        _default = p


def reset():
    global _default
    with _default_lock:
        if _default is not None and hasattr(_default, "stop"):
            _default.stop()
        _default = None


def note(event) -> None:
    """The call the rest of the product makes. Never raises, never blocks."""
    try:
        default().note(event)
    except Exception:  # noqa: BLE001
        return
