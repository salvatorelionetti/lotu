#!/usr/bin/env python3
"""Bus di eventi in-process di LOTU + tipi di evento condivisi.

Due piani distinti:
  - piano dati          -> EventBus (questo modulo): eventi strutturati, fan-out,
                           ogni sottoscrittore ha la PROPRIA coda;
  - piano notifiche     -> dispatch_queue di central_notifier: testo gia' formattato,
                           un solo consumatore che parla con Nextcloud Talk.

Namespace dei topic (gerarchico, separato da punti, sottoscrizione per prefisso):
  fritz.poll                  heartbeat: un ciclo di lettura del log e' terminato
  fritz.wifi.connected        WifiEvent normalizzato
  fritz.wifi.disconnected     WifiEvent normalizzato
  fritz.net.*                 (futuro) eventi WAN/IP
  presence.appeared|returned|left|roamed
  auth.* / fail2ban.*         (futuro)

Sottoscrivere 'fritz' riceve tutto cio' che inizia con 'fritz.'; '' riceve tutto.
"""

import collections
import queue
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Message:
    topic: str
    payload: Any
    ts: float


class EventBus:
    """Pub/sub minimale e thread-safe. publish() non blocca mai il produttore."""

    def __init__(self):
        self._lock = threading.Lock()
        self._subs = []                       # [(prefisso, queue.Queue)]
        self.dropped = collections.Counter()  # messaggi persi per coda piena

    def subscribe(self, prefix='', maxsize=10000):
        q = queue.Queue(maxsize=maxsize)
        with self._lock:
            self._subs.append((prefix.strip('.'), q))
        return q

    def publish(self, topic, payload=None):
        msg = Message(topic, payload, time.time())
        with self._lock:
            subs = list(self._subs)
        for prefix, q in subs:
            if prefix and topic != prefix and not topic.startswith(prefix + '.'):
                continue
            try:
                q.put_nowait(msg)
            except queue.Full:
                self.dropped[prefix or '*'] += 1
        return msg


@dataclass(frozen=True)
class WifiEvent:
    """Evento WLAN del FritzBox, normalizzato e indipendente dal parser."""
    ts: float          # epoch (l'orario del log e' locale/naive, come l'orologio del Pi)
    kind: str          # 'connected' | 'disconnected'
    mac: str           # 'AA:BB:CC:DD:EE:FF'
    band: str          # '2.4GHz' | '5GHz' | ...
    guest: bool        # accesso ospite
    hostname: str      # '' se non disponibile (tipico nei 'disconnected')
    ip: str            # '' se non disponibile
    speed: str         # '' se non disponibile
    raw: str = ''
    replay: bool = False   # True = proviene dalla lettura iniziale dello storico

    @property
    def link(self):
        """Chiave dell'associazione radio: banda + eventuale rete ospite."""
        return ('guest:' if self.guest else '') + self.band

    @classmethod
    def from_parsed(cls, ev, raw='', replay=False):
        """Costruisce un WifiEvent dall'oggetto restituito da parse_events2.parse_event()."""
        def clean(v):
            v = (v or '').strip()
            return '' if v in ('', '---') else v

        return cls(
            ts=datetime.fromisoformat(ev.date).timestamp(),
            kind='connected' if ev.kind.strip() == 'connected' else 'disconnected',
            mac=ev.mac.strip().upper().replace('-', ':'),
            band=ev.carrier.replace(',', '.').replace(' ', ''),
            guest='ospite' in ev.reason.lower(),
            hostname=clean(ev.hostname),
            ip=clean(ev.ip),
            speed=clean(ev.speed),
            raw=raw,
            replay=replay,
        )
