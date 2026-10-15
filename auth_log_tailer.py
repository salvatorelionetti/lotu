#!/usr/bin/env python3
"""Tail /var/log/auth.log and push parsed events to the central notification queue.

Provides run_auth_tailer(notify_queue, stop_event, cfg) used by central_notifier.
When invoked with --test it parses the WHOLE log from the first line, prints the
messages it would send instead of putting them on the queue, and exits at end of
file (no tail).

Recognised events (Debian/Raspberry Pi OS auth.log, classic syslog or ISO-8601
timestamps; IPv4 and IPv6; OpenSSH <= 9.7 "sshd" and >= 9.8 "sshd-session"):
  - sshd failures: failed password/publickey, invalid user, "Too many
    authentication failures", "maximum authentication attempts exceeded"
  - sshd accepted logins (flagged when the source is outside TRUSTED_NETS)
  - sshd scanner probes: invalid banner, no common algorithm, connection closed
    before authentication, reset during key exchange, no identification string
  - sshd per-source penalties ("drop connection ... penalty: ...", OpenSSH 9.8+)
  - sudo: commands, failed passwords, "NOT in sudoers", "command not allowed"
  - su: successful and failed switches
  - system: boot (systemd-logind "New seat seat0") and reboot/poweroff requests
  - local console login (off by default)
  - brute-force detection: N failed SSH logins from the same source within a time
    window produce ONE aggregated alert (then a cooldown). IPv6 sources are
    aggregated per /64, because one host owns the whole /64 and can rotate
    addresses freely.

Boot events are only seen if the tailer is already running when systemd-logind
writes the line; a tailer that starts later (it seeks to end of file) misses them.

Optional lotu.ini section:

    [auth]
    LOG_PATH = /var/log/auth.log
    TRUSTED_NETS =                  ; e.g. 192.168.0.0/16, 2a02:2455:1b1d::/48
    NOTIFY_ACCEPTED = true          ; ssh logins that succeeded
    NOTIFY_EACH_FAILURE = false     ; one message per failed attempt
    NOTIFY_SUDO = true
    NOTIFY_SU = true
    NOTIFY_BOOT = true              ; boot / reboot / poweroff
    NOTIFY_LOCAL_LOGIN = false      ; tty console logins (noisy with autologin)
    BRUTE_THRESHOLD = 5             ; failures from one source ...
    BRUTE_WINDOW = 120              ; ... within this many seconds
    BRUTE_COOLDOWN = 600            ; seconds before alerting again for same source
    PROBE_COOLDOWN = 3600           ; one probe/penalty alert per source per this many s
"""

import argparse
import collections
import configparser
import ipaddress
import os
import re
import time
from datetime import datetime

# <timestamp> <host> <process>[pid]: <message>
# timestamp is either "Oct 15 12:33:01" or "2026-10-15T12:33:01.123456+02:00"
LINE_RE = re.compile(
    r'^(?P<ts>\S+(?:\s+\d+\s+[\d:]+)?)\s+(?P<host>\S+)\s+'
    r'(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$'
)

# --- sshd ------------------------------------------------------------------
SSH_FAILED_RE = re.compile(
    r'Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) '
    r'from (?P<ip>\S+) port (?P<port>\d+)'
)
SSH_INVALID_RE = re.compile(r'Invalid user (?P<user>\S*) from (?P<ip>\S+)')
SSH_CLOSED_INVALID_RE = re.compile(
    r'(?:Connection closed by|Disconnected from) invalid user (?P<user>\S*) '
    r'(?P<ip>\S+) port \d+'
)
SSH_TOOMANY_RE = re.compile(
    r'Disconnecting (?:invalid|authenticating) user (?P<user>\S+) (?P<ip>\S+) '
    r'port \d+: Too many authentication failures'
)
SSH_ACCEPTED_RE = re.compile(
    r'Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)
SSH_MAXAUTH_RE = re.compile(
    r'maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) '
    r'from (?P<ip>\S+)'
)
# OpenSSH 9.8+ PerSourcePenalties: the listener (process "sshd") logs the source
# in brackets: drop connection #2 from [2a02:...]:50008 on [...]:22 penalty: ...
SSH_PENALTY_RE = re.compile(
    r'drop connection #\d+ from \[(?P<ip>[^\]]+)\]:\d+ on \S+ penalty: (?P<why>.*)$'
)
# Scanner-like noise: (regex, short description). Each has an "ip" group.
SSH_PROBE_PATTERNS = [
    (re.compile(r'banner exchange: Connection from (?P<ip>\S+) port \d+: invalid format'),
     'invalid SSH banner'),
    (re.compile(r'Unable to negotiate with (?P<ip>\S+) port \d+: no matching'),
     'no common key-exchange/cipher/key algorithm'),
    (re.compile(r'Connection closed by (?P<ip>[0-9a-fA-F:.]+) port \d+ \[preauth\]'),
     'connection closed before authentication'),
    (re.compile(r'Did not receive identification string from (?P<ip>\S+)'),
     'no identification string'),
    (re.compile(r'Bad protocol version identification .* from (?P<ip>\S+) port'),
     'bad protocol version'),
    (re.compile(r'Timeout before authentication for connection from (?P<ip>\S+) to'),
     'authentication timeout'),
]
# "error: kex_exchange_identification: ..." carries no address; the very next line
# from the same pid ("Connection reset by <ip> port N") does. Remember the pid.
KEX_ERR_RE = re.compile(r'error: kex_exchange_identification:')
RESET_RE = re.compile(r'Connection reset by (?P<ip>\S+) port \d+$')
_KEX_PIDS = collections.OrderedDict()

# --- sudo / su / system -------------------------------------------------------
SUDO_CMD_RE = re.compile(
    r'^\s*(?P<user>\S+)\s*:.*?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$'
)
SUDO_BADPW_RE = re.compile(r'^\s*(?P<user>\S+)\s*:\s*(?P<n>\d+) incorrect password attempts')
SUDO_DENIED_RE = re.compile(
    r'^\s*(?P<user>\S+)\s*:\s*(?P<why>user NOT in sudoers|command not allowed)'
)
SU_RE = re.compile(r'^(?P<ok>FAILED SU|\(to) ?(?P<rest>.*)$')
SYSTEM_DOWN_RE = re.compile(r'System is (?P<what>rebooting|powering off|halting)')
LOGIN_OPEN_RE = re.compile(r'session opened for user (?P<user>[^\s(]+)')


def _parse_ts(ts):
    """Convert a log timestamp to epoch seconds, or None if unparseable.

    Handles ISO-8601 ("2026-10-15T12:33:01.123456+02:00") and classic syslog
    ("Oct 15 12:33:01", no year: assume the current one, or the previous one if
    that would put the line more than a day in the future, e.g. Dec log read in Jan).
    """
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        pass
    try:
        now = datetime.now()
        dt = datetime.strptime(f"{now.year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")
        if (dt - now).total_seconds() > 86400:
            dt = dt.replace(year=now.year - 1)
        return dt.timestamp()
    except ValueError:
        return None


def _source_key(ip):
    """Aggregation key for a source: the address for IPv4, the /64 for IPv6."""
    if not ip:
        return 'unknown'
    ip = ip.strip('[]')
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def _load_nets(text):
    nets = []
    for part in (text or '').replace(';', ',').split(','):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            pass  # ignore malformed entries rather than crash the thread
    return nets


def _in_nets(ip, nets):
    if not ip or not nets:
        return False
    try:
        addr = ipaddress.ip_address(ip.strip('[]'))
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def _flag(cfg, key, default):
    try:
        return cfg.getboolean('auth', key, fallback=default)
    except ValueError:
        return default


def _num(cfg, key, default):
    try:
        return cfg.getint('auth', key, fallback=default)
    except ValueError:
        return default


class BruteForceTracker:
    """Counts events per source in a sliding window and rate-limits alerts.

    With threshold=1 it degrades to a plain "alert once per source per cooldown"
    limiter, which is how it is used for probes and penalties.
    """

    def __init__(self, threshold, window, cooldown):
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown
        self._hits = collections.defaultdict(collections.deque)
        self._last_alert = {}

    def record(self, key, now=None):
        """Return the event count if an alert should fire now, else None."""
        now = time.time() if now is None else now
        dq = self._hits[key]
        dq.append(now)
        while dq and now - dq[0] > self.window:
            dq.popleft()
        if len(dq) >= self.threshold:
            last = self._last_alert.get(key)
            if last is None or now - last >= self.cooldown:
                self._last_alert[key] = now
                return len(dq)
        return None


def parse_auth_line(line):
    """Parse one auth.log line.

    Returns a dict {kind, ip, text, ts} or None if the line is not interesting.
    kind is one of: ssh_failed, ssh_invalid, ssh_toomany, ssh_maxauth,
    ssh_accepted, ssh_probe, ssh_penalty, sudo_cmd, sudo_fail, su_ok, su_fail,
    boot, reboot, local_login. ts is the log timestamp as epoch seconds (None if
    it could not be parsed).

    Not strictly stateless: it remembers the pid of recent kex_exchange_identification
    errors so the following "Connection reset by <ip>" line can be attributed.
    """
    ev = _parse_event(line)
    if ev is not None:
        m = LINE_RE.match(line)
        ev['ts'] = _parse_ts(m.group('ts')) if m else None
    return ev


def _parse_event(line):
    m = LINE_RE.match(line)
    if not m:
        return None
    proc, msg, host, pid = m.group('proc'), m.group('msg'), m.group('host'), m.group('pid')

    # "sshd" (OpenSSH <= 9.7, and the listener on 9.8+), "sshd-session" and
    # "sshd-auth" (9.8+/10.x): the per-connection messages moved to sshd-session.
    if proc.startswith('sshd'):
        mm = SSH_ACCEPTED_RE.search(msg)
        if mm:
            return {'kind': 'ssh_accepted', 'ip': mm['ip'],
                    'text': f"SSH login OK: {mm['user']} from {mm['ip']}:{mm['port']} "
                            f"({mm['method']}) on {host}"}
        mm = SSH_FAILED_RE.search(msg)
        if mm:
            return {'kind': 'ssh_failed', 'ip': mm['ip'],
                    'text': f"SSH login FAILED: {mm['user']} from {mm['ip']}:{mm['port']} "
                            f"({mm['method']}) on {host}"}
        mm = SSH_TOOMANY_RE.search(msg)
        if mm:
            return {'kind': 'ssh_toomany', 'ip': mm['ip'],
                    'text': f"SSH too many authentication failures: {mm['user']} "
                            f"from {mm['ip']} on {host}"}
        mm = SSH_MAXAUTH_RE.search(msg)
        if mm:
            return {'kind': 'ssh_maxauth', 'ip': mm['ip'],
                    'text': f"SSH max auth attempts exceeded: {mm['user']} from {mm['ip']} on {host}"}
        mm = SSH_INVALID_RE.search(msg)
        if mm:
            return {'kind': 'ssh_invalid', 'ip': mm['ip'],
                    'text': f"SSH invalid user: '{mm['user']}' from {mm['ip']} on {host}"}
        mm = SSH_CLOSED_INVALID_RE.search(msg)
        if mm:
            return {'kind': 'ssh_invalid', 'ip': mm['ip'],
                    'text': f"SSH invalid user dropped: '{mm['user']}' from {mm['ip']} on {host}"}
        mm = SSH_PENALTY_RE.search(msg)
        if mm:
            return {'kind': 'ssh_penalty', 'ip': mm['ip'],
                    'text': f"sshd throttled {mm['ip']} on {host} (penalty: {mm['why']})"}
        for rx, what in SSH_PROBE_PATTERNS:
            mm = rx.search(msg)
            if mm:
                return {'kind': 'ssh_probe', 'ip': mm['ip'],
                        'text': f"SSH probe from {mm['ip']} on {host}: {what}"}
        if pid is not None:
            if KEX_ERR_RE.search(msg):
                _KEX_PIDS[pid] = True
                while len(_KEX_PIDS) > 256:
                    _KEX_PIDS.popitem(last=False)
                return None
            mm = RESET_RE.search(msg)
            if mm and _KEX_PIDS.pop(pid, None):
                return {'kind': 'ssh_probe', 'ip': mm['ip'],
                        'text': f"SSH probe from {mm['ip']} on {host}: "
                                f"connection reset during key exchange"}
        return None

    if proc == 'sudo':
        # Failures first: "user : 3 incorrect password attempts ; TTY=... ; COMMAND=..."
        # and "user : user NOT in sudoers ; ... COMMAND=..." also contain USER=/COMMAND=
        # and would otherwise be reported as ordinary commands.
        mm = SUDO_BADPW_RE.match(msg)
        if mm:
            return {'kind': 'sudo_fail', 'ip': None,
                    'text': f"sudo: {mm['user']} had {mm['n']} incorrect password attempts on {host}"}
        mm = SUDO_DENIED_RE.match(msg)
        if mm:
            return {'kind': 'sudo_fail', 'ip': None,
                    'text': f"sudo DENIED: {mm['user']}: {mm['why']} on {host}: {msg.strip()}"}
        if 'authentication failure' in msg and 'pam_unix(sudo' in msg:
            return {'kind': 'sudo_fail', 'ip': None,
                    'text': f"sudo authentication failure on {host}: {msg}"}
        mm = SUDO_CMD_RE.match(msg)
        if mm:
            return {'kind': 'sudo_cmd', 'ip': None,
                    'text': f"sudo: {mm['user']} -> {mm['target']}: {mm['cmd'].strip()} on {host}"}
        return None

    if proc == 'su' or proc.startswith('su-'):
        mm = SU_RE.match(msg)
        if mm:
            failed = mm['ok'] == 'FAILED SU'
            detail = msg if failed else '(to ' + mm['rest']
            return {'kind': 'su_fail' if failed else 'su_ok', 'ip': None,
                    'text': f"su {'FAILED' if failed else 'OK'}: {detail} on {host}"}
        return None

    if proc == 'systemd-logind':
        if msg.startswith('New seat seat0'):
            return {'kind': 'boot', 'ip': None, 'text': f"System boot detected on {host}"}
        mm = SYSTEM_DOWN_RE.search(msg)
        if mm:
            return {'kind': 'reboot', 'ip': None,
                    'text': f"System is {mm['what']} on {host}"}
        return None

    if proc == 'login':
        mm = LOGIN_OPEN_RE.search(msg)
        if mm and 'pam_unix(login:session)' in msg:
            return {'kind': 'local_login', 'ip': None,
                    'text': f"Local console login: {mm['user']} on {host}"}
        return None

    return None


def _open_log(path, from_start):
    fh = open(path, 'r', encoding='utf-8', errors='replace')
    if not from_start:
        fh.seek(0, os.SEEK_END)
    return fh


def run_auth_tailer(notify_queue, stop_event, cfg=None, test_mode=False,
                    max_iterations=None, from_start=False, log_path=None,
                    stop_at_eof=False):
    """Read auth.log and emit structured notifications into notify_queue.

    notify_queue: queue.Queue-like object (has put)
    stop_event: threading.Event
    cfg: configparser.ConfigParser or None (will read lotu.ini if None)
    test_mode: if True the caller is expected to pass a PrintQueue wrapper
    max_iterations: optional limit on processed lines (useful for tests)
    from_start: read the existing file content instead of only new lines (tests)
    log_path: override LOG_PATH from the config
    stop_at_eof: return as soon as the end of the file is reached instead of
                 following it (one-shot scan; used by --test). Combine with
                 from_start=True to examine the whole file.
    """
    print('AUTH:run_auth_tailer!!!')
    print('AUTH:cfg', cfg, cfg.sections())
    #cfg = cfg or configparser.ConfigParser()
    #if not cfg.sections():
    #    cfg.read('lotu.ini')

    log_path = log_path or cfg.get('auth', 'LOG_PATH', fallback='/var/log/auth.log')
    print('AUTH:log_path', log_path)
    room_token = cfg.get('talk', 'ROOM_TOKEN', fallback=None)

    notify_accepted = _flag(cfg, 'NOTIFY_ACCEPTED', True)
    notify_each_failure = _flag(cfg, 'NOTIFY_EACH_FAILURE', False)
    notify_sudo = _flag(cfg, 'NOTIFY_SUDO', True)
    notify_su = _flag(cfg, 'NOTIFY_SU', True)
    notify_boot = _flag(cfg, 'NOTIFY_BOOT', True)
    notify_local = _flag(cfg, 'NOTIFY_LOCAL_LOGIN', False)
    trusted = _load_nets(cfg.get('auth', 'TRUSTED_NETS', fallback=''))

    print('auth_log_tailer: notify_each_failure', notify_each_failure)

    brute = BruteForceTracker(
        threshold=_num(cfg, 'BRUTE_THRESHOLD', 5),
        window=_num(cfg, 'BRUTE_WINDOW', 120),
        cooldown=_num(cfg, 'BRUTE_COOLDOWN', 600),
    )
    probe_cooldown = _num(cfg, 'PROBE_COOLDOWN', 3600)
    probes = BruteForceTracker(threshold=1, window=1, cooldown=probe_cooldown)
    penalties = BruteForceTracker(threshold=1, window=1, cooldown=probe_cooldown)

    # If log doesn't exist, exit silently (central notifier may start before file appears)
    if not os.path.exists(log_path):
        return

    def emit(text, silent=False):
        payload = {
            'source': 'auth',
            'text': f"[auth] {text}",
            'room': room_token,
            'silent': silent,
        }
        try:
            notify_queue.put(payload)
        except Exception:
            # best-effort: ignore failures from the notify queue
            pass

    iterations = 0
    fh = None
    try:
        fh = _open_log(log_path, from_start)
        inode = os.fstat(fh.fileno()).st_ino
        while not stop_event.is_set():
            if max_iterations is not None and iterations >= max_iterations:
                return

            line = fh.readline()
            if not line:
                if stop_at_eof:
                    return
                # Idle: check for rotation (new inode) or truncation, then wait
                try:
                    st = os.stat(log_path)
                    if st.st_ino != inode:
                        fh.close()
                        fh = _open_log(log_path, True)  # new file: read from start
                        inode = os.fstat(fh.fileno()).st_ino
                        continue
                    if st.st_size < fh.tell():
                        fh.seek(0)
                        continue
                except OSError:
                    pass  # file briefly missing during rotation
                stop_event.wait(0.5)
                continue
            else:
                print('AUTH GOT:', line)

            iterations += 1
            clean = line.strip()
            if not clean:
                continue

            ev = parse_auth_line(clean)
            if ev is None:
                continue

            kind = ev['kind']
            src = ev.get('ip')
            now = ev.get('ts')  # the log's own timestamp: replaying an old file is faithful
            key = _source_key(src)
            shown = src if key == src or not src else f"{src} (net {key})"

            if kind in ('ssh_failed', 'ssh_invalid', 'ssh_maxauth', 'ssh_toomany'):
                count = brute.record(key, now=now)
                if count is not None:
                    emit(f"POSSIBLE BRUTE FORCE: {count} SSH failures from {shown} "
                         f"in the last {brute.window}s")
                if notify_each_failure or kind in ('ssh_maxauth', 'ssh_toomany'):
                    emit(ev['text'], silent=True)
            elif kind == 'ssh_accepted':
                if trusted and not _in_nets(src, trusted):
                    emit(ev['text'] + " - SOURCE NOT IN TRUSTED_NETS")
                elif notify_accepted:
                    emit(ev['text'])
            elif kind == 'ssh_probe':
                # scanner noise: one quiet message per source per PROBE_COOLDOWN;
                # skipped entirely for trusted networks
                if _in_nets(src, trusted):
                    continue
                if probes.record(key, now=now) is not None:
                    emit(ev['text'], silent=True)
            elif kind == 'ssh_penalty':
                # sshd itself is throttling a source: worth an audible message, once
                if penalties.record(key, now=now) is not None:
                    emit(ev['text'])
            elif kind == 'sudo_cmd':
                if notify_sudo:
                    emit(ev['text'], silent=True)
            elif kind == 'sudo_fail':
                emit(ev['text'])
            elif kind in ('su_ok', 'su_fail'):
                if notify_su or kind == 'su_fail':
                    emit(ev['text'], silent=(kind == 'su_ok'))
            elif kind == 'boot':
                if notify_boot:
                    emit(ev['text'])
            elif kind == 'reboot':
                if notify_boot:
                    emit(ev['text'], silent=True)
            elif kind == 'local_login':
                if notify_local:
                    emit(ev['text'], silent=True)
    except Exception:
        # Don't let exceptions crash the thread; return to allow restart by service
        return
    finally:
        if fh is not None:
            try:
                fh.close()
            except Exception:
                pass


class PrintQueue:
    """Simple queue-like object that prints put() payloads to stdout (for test mode)."""
    def put(self, item):
        print("[TEST-AUTH]", item.get('text'))


def main():
    p = argparse.ArgumentParser(description='auth.log tailer test/runner')
    p.add_argument('--test', action='store_true',
                   help='Test mode: parse the WHOLE log from the first line, print the '
                        'messages and exit at end of file (no tail)')
    p.add_argument('--once', action='store_true',
                   help='Stop after processing a single line (useful in test)')
    p.add_argument('--from-start', action='store_true',
                   help='Normal mode only: parse existing content instead of only new lines')
    p.add_argument('--file', help='Path to an auth.log to parse (overrides LOG_PATH)')
    p.add_argument('--max-lines', type=int, default=None,
                   help='Stop after N processed lines')
    args = p.parse_args()

    import threading
    stop = threading.Event()

    cfg = configparser.ConfigParser()
    cfg.read('lotu.ini')

    max_iter = 1 if args.once else args.max_lines

    if args.test:
        q = PrintQueue()
        try:
            # one-shot: read every line from the beginning, terminate at EOF
            run_auth_tailer(q, stop, cfg=cfg, test_mode=True, max_iterations=max_iter,
                            from_start=True, log_path=args.file, stop_at_eof=True)
        except KeyboardInterrupt:
            pass
    else:
        # Normal mode: run with a real queue (import here to avoid heavy deps)
        import queue
        q = queue.Queue()
        try:
            run_auth_tailer(q, stop, cfg=cfg, max_iterations=max_iter,
                            from_start=args.from_start, log_path=args.file)
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
