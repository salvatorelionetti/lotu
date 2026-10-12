#!/usr/bin/env python3
"""Tail the fail2ban log and push events to the central notification queue.

Provides run_fail2ban_tailer(notify_queue, stop_event, cfg) used by central_notifier.
When invoked with --test it prints the messages it would send instead of putting
them on the queue.
"""

import argparse
import configparser
import os
import time


def run_fail2ban_tailer(notify_queue, stop_event, cfg=None, test_mode=False, max_iterations=None):
    """Read the fail2ban log and emit structured notifications into notify_queue.

    notify_queue: queue.Queue-like object (has put)
    stop_event: threading.Event
    cfg: configparser.ConfigParser or None (will read lotu.ini if None)
    test_mode: if True, use notify_queue.put to print instead of enqueueing (caller may
               provide a PrintQueue wrapper)
    max_iterations: optional limit for loops (useful for tests)
    """
    cfg = cfg or configparser.ConfigParser()
    if not cfg.sections():
        cfg.read('lotu.ini')

    log_path = cfg.get('fail2ban', 'LOG_PATH', fallback='/var/log/fail2ban.log')
    room_token = cfg.get('talk', 'ROOM_TOKEN', fallback=None)

    # If log doesn't exist, exit silently (central notifier may start before file appears)
    if not os.path.exists(log_path):
        return

    iterations = 0
    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as fh:
            fh.seek(0, os.SEEK_END)
            while not stop_event.is_set():
                if max_iterations is not None and iterations >= max_iterations:
                    return
                line = fh.readline()
                if not line:
                    # use stop_event.wait to be responsive to shutdown
                    stop_event.wait(0.5)
                    continue

                clean = line.strip()
                if not clean:
                    continue

                # Minimal heuristics for interesting lines
                if any(token in clean for token in ('Ban ', 'Unban ', 'fail2ban.actions')):
                    payload = {
                        'source': 'fail2ban',
                        'text': f"[fail2ban] {clean}",
                        'room': room_token,
                        'silent': False,
                    }
                    try:
                        notify_queue.put(payload)
                    except Exception:
                        # best-effort: ignore failures from the notify queue
                        pass

                iterations += 1
    except Exception:
        # Don't let exceptions crash the thread; return to allow restart by service
        return


class PrintQueue:
    """Simple queue-like object that prints put() payloads to stdout (for test mode)."""
    def put(self, item):
        print("[TEST-FAIL2BAN]", item.get('text'))


def main():
    p = argparse.ArgumentParser(description='fail2ban tailer test/runner')
    p.add_argument('--test', action='store_true', help='Run in test mode and print messages')
    p.add_argument('--once', action='store_true', help='Run a single iteration (useful in test)')
    args = p.parse_args()

    import threading
    stop = threading.Event()

    cfg = configparser.ConfigParser()
    cfg.read('lotu.ini')

    if args.test:
        q = PrintQueue()
        # run single iteration if requested, otherwise run until Ctrl-C
        max_iter = 1 if args.once else None
        try:
            run_fail2ban_tailer(q, stop, cfg=cfg, test_mode=True, max_iterations=max_iter)
        except KeyboardInterrupt:
            pass
    else:
        # Normal mode: run with a real queue (import here to avoid heavy deps)
        import queue
        q = queue.Queue()
        try:
            run_fail2ban_tailer(q, stop, cfg=cfg)
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
