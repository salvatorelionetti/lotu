#!/usr/bin/env python3
"""Central notifier for LOTU.

This service is the only module allowed to deliver messages to Nextcloud Talk.
Producer threads (FritzBox poller, fail2ban tailer) only push structured items
onto a thread-safe queue; this consumer serializes their delivery.
"""

import configparser
import os
import queue
import signal
import sys
import threading
import traceback

import talk2

from fail2ban_tailer import run_fail2ban_tailer
from fritz_log_read2 import run_fritz_poller
from auth_log_tailer import run_auth_tailer

CONFIG = configparser.ConfigParser()
CONFIG.read('lotu.ini')

SEND_LOCK = threading.Lock()


def get_bot_secret(cfg):
    talk_cfg = cfg['talk']
    secret = talk_cfg.get('BOT_SECRET') or os.environ.get('NC_BOT_SECRET')
    if secret:
        return secret

    secret_file = talk_cfg.get('BOT_SECRET_FILE') or os.environ.get('NC_BOT_SECRET_FILE')
    if secret_file:
        return talk2.load_secret(secret_file, None)
    return None


def send_to_nextcloud(item, cfg):
    text = (item.get('text') or '').strip()
    if not text:
        return

    room_token = item.get('room') or cfg['talk'].get('ROOM_TOKEN')
    if not room_token:
        print('room token missing; dropping message', file=sys.stderr)
        return

    bot_secret = get_bot_secret(cfg)
    if not bot_secret:
        print('bot secret missing; dropping message', file=sys.stderr)
        return

    with SEND_LOCK:
        try:
            response = talk2.send_bot_message(
                cfg['talk']['NC_URL'],
                room_token,
                bot_secret,
                text,
                reply_to=item.get('reply_to'),
                silent=bool(item.get('silent', False)),
                verify_tls=not bool(item.get('insecure', False)),
            )
            if response is not None and getattr(response, 'status_code', 0) not in (200, 201, 202):
                print(f"HTTP {response.status_code}: {response.text[:200]}", file=sys.stderr)
        except Exception:
            traceback.print_exc(file=sys.stderr)


def notifier_loop(stop_event, dispatch_queue, cfg):
    while not stop_event.is_set():
        try:
            item = dispatch_queue.get(timeout=1)
        except queue.Empty:
            continue

        try:
            send_to_nextcloud(item, cfg)
        except Exception:
            traceback.print_exc(file=sys.stderr)
        finally:
            dispatch_queue.task_done()


def start_workers(dispatch_queue, stop_event, cfg):
    assert(False)
    workers = [
        threading.Thread(
            target=run_fritz_poller,
            args=(dispatch_queue, stop_event, cfg),
            name='fritz-poller',
            daemon=True,
        ),
        threading.Thread(
            target=run_fail2ban_tailer,
            args=(dispatch_queue, stop_event, cfg),
            name='fail2ban-tailer',
            daemon=True,
        ),
        threading.Thread(
            target=run_auth_tailer,
            args=(dispatch_queue, stop_event, cfg),
            name='auth-log-tailer',
            daemon=True,
        ),
    ]

    for thread in workers:
        print(thread)
        thread.start()

    return workers


def main():
    print('IN MAIN2')
    assert(1==0)
    stop_event = threading.Event()

    def _stop_handler(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, _stop_handler)
    signal.signal(signal.SIGTERM, _stop_handler)

    dispatch_queue = queue.Queue()
    start_workers(dispatch_queue, stop_event, CONFIG)
    notifier_loop(stop_event, dispatch_queue, CONFIG)
    print('central_notifier stopped')

print('BEFORE MAIN')
if __name__ == '__main__':
    print('BEFORE MAIN2')
    main()
