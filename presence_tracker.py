#!/usr/bin/env python3
"""Presence tracker: trasforma gli eventi WLAN del FritzBox in presenza/assenza.

Problema: un cambio banda (2.4 <-> 5 GHz, band steering) nel log reale del FritzBox
appare come un nuovo 'connesso' sulla nuova banda, SENZA 'disconnesso' della vecchia
(verificato su un log reale: l'evento 766 "commutato (Band-Steering)" e' sempre
accompagnato dal solo 'connesso' sulla nuova banda). Un dispositivo ha quindi UNA sola
associazione corrente (`link`): ogni nuovo 'connesso' sostituisce la precedente, e un
'disconnesso' riferito a un'associazione gia' sostituita viene ignorato (cosi' non
restano associazioni "fantasma"). Quando l'associazione corrente cade non si dichiara
subito l'uscita: parte un periodo di tolleranza (GRACE). Se entro GRACE compare un nuovo
'connesso' (qualunque banda) e' una riconnessione o un cambio banda; altrimenti
l'uscita viene confermata.

Proprieta' importanti:
  - indipendente dall'ordine di connect/disconnect nello stesso istante quando le
    bande sono diverse (roaming "make-before-break" o "break-before-make");
  - l'uscita e' confermata solo quando il "watermark" (ultimo istante certamente
    letto dal log, avanzato dagli eventi e dagli heartbeat 'fritz.poll') supera
    left_at + GRACE: se il poller e' fermo o cieco non genera false uscite;
  - gli eventi con replay=True ricostruiscono lo stato senza notificare.

Pubblica sul bus: presence.appeared | returned | left | roamed
e (opzionale) mette messaggi testuali su notify_queue (-> central_notifier -> Talk).

Sezione opzionale di lotu.ini:

    [presence]
    GRACE = 90               ; secondi di tolleranza prima di dichiarare l'uscita
    ROOM_TOKEN =             ; stanza Talk per questi messaggi (default: [talk] ROOM_TOKEN)
    NOTIFY_DEVICES =         ; MAC o hostname separati da virgole: solo questi generano
                             ; messaggi su Talk; vuoto = tutti. Il bus riceve sempre tutto
    WATCH_MACS =             ; limita il TRACCIAMENTO (e il bus) a questi MAC; vuoto = tutti

    [presence_aliases]       ; <MAC o hostname> = <nome da mostrare nei messaggi>
    B6-EF-18-65-39-85 = Telefono Salvatore   ; MAC con i TRATTINI (':' rompe ConfigParser)
    Galaxy-A34-5G = Telefono Salvatore       ; oppure per hostname (maiuscole ininfluenti)
    ; Nel messaggio compare "Alias (hostname)"; l'alias vale anche in NOTIFY_DEVICES.
    NOTIFY_LEFT = true
    NOTIFY_RETURNED = true
    NOTIFY_APPEARED = false  ; MAC mai visto prima
    NOTIFY_ROAM = false      ; cambi banda (messaggio silenzioso)

Test offline su un file di log:  python3 presence_tracker.py log.txt [--grace 90] [--newest-first]
"""

import argparse
import queue
import time
import traceback
from dataclasses import dataclass, field

from lotu_bus import WifiEvent


@dataclass
class Device:
    mac: str
    hostname: str = ''
    ip: str = ''
    link: str | None = None                   # associazione radio corrente (None = nessuna)
    present: bool = False
    known: bool = False                       # visto almeno un evento
    last_link: str = ''
    left_at: float | None = None              # uscita "in sospeso" (grace in corso)
    left_quiet: bool = False                  # l'uscita in sospeso viene da un replay
    gone_since: float | None = None           # uscita confermata (per la durata assenza)


class PresenceTracker:
    def __init__(self, emit, grace=90, watch=None, name_lookup=None, log=None):
        """emit(kind, info: dict) viene chiamata a ogni transizione notificabile.
        log(*args) (opzionale) riceve le tracce di diagnostica."""
        self.log = log or (lambda *a: None)
        self.emit = emit
        self.grace = grace
        self.watch = set(watch or ())
        self.name_lookup = name_lookup
        self.devices = {}
        self.watermark = 0.0

    # -- utilita' ---------------------------------------------------------------
    def _name(self, d):
        db_name = self.name_lookup(d.mac) if self.name_lookup else ''
        return d.hostname or db_name or d.mac

    def _fire(self, kind, d, ts, **extra):
        info = {'kind': kind, 'mac': d.mac, 'name': self._name(d),
                'hostname': d.hostname, 'ip': d.ip, 'ts': ts, **extra}
        self.emit(kind, info)

    # -- tempo ------------------------------------------------------------------
    def advance(self, ts):
        """Avanza il watermark e conferma le uscite il cui grace e' scaduto."""
        if ts > self.watermark:
            self.watermark = ts
        for d in self.devices.values():
            if d.left_at is not None and self.watermark > d.left_at + self.grace:
                since, d.left_at = d.left_at, None
                d.present = False
                d.gone_since = since
                if not d.left_quiet:
                    self._fire('left', d, since, link=d.last_link)

    # -- eventi -----------------------------------------------------------------
    def on_event(self, e: WifiEvent):
        self.advance(e.ts)    # gli eventi arrivano in ordine cronologico
        self.log('evento', e.kind, e.mac, e.link, time.strftime('%H:%M:%S', time.localtime(e.ts)),
                 'replay' if e.replay else 'live')
        if self.watch and e.mac not in self.watch:
            self.log('  -> IGNORATO: MAC non in WATCH_MACS', sorted(self.watch))
            return
        d = self.devices.setdefault(e.mac, Device(e.mac))
        if e.kind == 'connected':
            if e.hostname:
                d.hostname = e.hostname
            if e.ip:
                d.ip = e.ip
            self._connected(d, e)
        else:
            self._disconnected(d, e)

    def _connected(self, d, e):
        prev = d.link
        d.link = e.link               # il nuovo 'connesso' sostituisce l'associazione precedente
        if d.present:
            if d.left_at is not None:
                # Rientro entro il grace: riconnessione o cambio banda.
                d.left_at = None
                if e.link != d.last_link and not e.replay:
                    self._fire('roamed', d, e.ts, from_link=d.last_link, to_link=e.link)
            elif prev is not None and prev != e.link and not e.replay:
                # band steering / roaming: nuovo connect senza disconnect della vecchia banda
                self._fire('roamed', d, e.ts, from_link=prev, to_link=e.link)
        else:
            first = not d.known
            d.present = True
            if not e.replay:
                away = (e.ts - d.gone_since) if d.gone_since else None
                self._fire('appeared' if first else 'returned', d, e.ts,
                           link=e.link, away_s=away)
        d.known = True
        d.last_link = e.link

    def _disconnected(self, d, e):
        if not d.known:
            # disconnessione senza connessione nota: era presente prima della
            # finestra di log disponibile
            d.present = True
        d.known = True
        if d.link is not None and e.link != d.link:
            return    # disconnect di un'associazione gia' sostituita da una piu' recente
        d.link = None
        if d.present and d.left_at is None:
            d.left_at = e.ts
            d.left_quiet = e.replay
            d.last_link = e.link
            self.log('  -> uscita IN SOSPESO', d.mac, '; confermo quando il watermark supera',
                     time.strftime('%H:%M:%S', time.localtime(e.ts + self.grace)),
                     '(silenziosa: replay)' if e.replay else '')


# -- presentazione / integrazione ---------------------------------------------------
def _fmt_dur(sec):
    if sec is None:
        return ''
    if sec < 90:
        return f", assente da {int(sec)} s"
    if sec < 5400:
        return f", assente da {int(sec / 60)} min"
    return f", assente da {sec / 3600:.1f} h"


def format_message(kind, info):
    hhmmss = time.strftime('%H:%M:%S', time.localtime(info['ts']))
    name, mac = info.get('label') or info['name'], info['mac']
    if kind == 'left':
        return f"🔴 {name} è uscito (ultimo link {info['link']}, alle {hhmmss}) [{mac}]"
    if kind == 'returned':
        return f"🟢 {name} è tornato ({info['link']}, alle {hhmmss}{_fmt_dur(info.get('away_s'))}) [{mac}]"
    if kind == 'appeared':
        return f"🆕 {name} visto per la prima volta ({info['link']}, alle {hhmmss}) [{mac}]"
    if kind == 'roamed':
        return f"🔄 {name}: cambio banda {info['from_link']} → {info['to_link']} ({hhmmss})"
    return f"{kind} {info}"


def _norm_key(item):
    """MAC (con ':' o '-') -> 'AA:BB:CC:DD:EE:FF'; altrimenti hostname/alias in minuscolo."""
    item = item.strip()
    if len(item) == 17 and item.count(':') + item.count('-') == 5:
        return item.upper().replace('-', ':')
    return item.lower()


def run_presence_tracker(notify_queue, stop_event, cfg, bus, inbox=None):
    """Entry point per central_notifier. `inbox` = bus.subscribe('fritz'), creata prima
    dell'avvio dei produttori per non perdere i primi messaggi."""
    inbox = inbox or bus.subscribe('fritz')
    # stanza dedicata alla presenza; se assente si usa quella di [talk]
    room = (cfg.get('presence', 'ROOM_TOKEN', fallback='').strip()
            or cfg.get('talk', 'ROOM_TOKEN', fallback=None))

    def flag(key, default):
        try:
            return cfg.getboolean('presence', key, fallback=default)
        except ValueError:
            return default

    notify = {'left': flag('NOTIFY_LEFT', True), 'returned': flag('NOTIFY_RETURNED', True),
              'appeared': flag('NOTIFY_APPEARED', False), 'roamed': flag('NOTIFY_ROAM', False)}
    try:
        grace = cfg.getint('presence', 'GRACE', fallback=90)
    except ValueError:
        grace = 90
    watch = {m.strip().upper().replace('-', ':')
             for m in cfg.get('presence', 'WATCH_MACS', fallback='').split(',') if m.strip()}

    name_lookup = None
    try:
        import annota_mac
        annot = annota_mac.AnnotatoreMac('mac_hostname_ip.tsv')
        name_lookup = lambda mac: (annot.cerca(mac) or ('',))[0]
    except Exception:
        pass   # senza DB si usa l'hostname del log o il MAC

    # Dispositivi per cui inviare messaggi su Talk: MAC oppure hostname (senza distinzione
    # maiuscole/minuscole). Vuoto = tutti. Non limita il tracciamento ne' il bus.
    devices = {_norm_key(i) for i in cfg.get('presence', 'NOTIFY_DEVICES', fallback='').split(',')
               if i.strip()}

    # Alias: [presence_aliases]  <MAC o hostname> = <nome da mostrare>
    # ATTENZIONE: ConfigParser tratta ':' come separatore chiave/valore, quindi i MAC nelle
    # chiavi vanno scritti con i trattini (B6-EF-18-65-39-85). Valori con '%' ammessi (raw).
    aliases = {}
    if cfg.has_section('presence_aliases'):
        for key, value in cfg.items('presence_aliases', raw=True):
            if key.strip() and value.strip():
                aliases[_norm_key(key)] = value.strip()

    def wanted(info):
        return (not devices or info['mac'] in devices
                or info['name'].lower() in devices
                or (info['hostname'] or '').lower() in devices
                or info['alias'].lower() in devices)

    def emit(kind, info):
        # alias: prima per MAC, poi per hostname (log o TSV)
        alias = (aliases.get(info['mac']) or aliases.get((info['hostname'] or '').lower())
                 or aliases.get(info['name'].lower()) or '')
        info['alias'] = alias
        info['label'] = (f"{alias} ({info['name']})"
                         if alias and alias.lower() != info['name'].lower() else info['name'])
        bus.publish(f'presence.{kind}', info)      # il bus riceve sempre tutto
        if notify.get(kind) and wanted(info):
            notify_queue.put({'source': 'presence', 'text': format_message(kind, info),
                              'room': room, 'silent': kind in ('roamed', 'appeared')})

    debug = flag('DEBUG', False)
    log = (lambda *a: print('PRESENCE', *a, flush=True)) if debug else None
    tracker = PresenceTracker(emit, grace=grace, watch=watch, name_lookup=name_lookup, log=log)
    print('PRESENCE avviato: grace', grace, '| watch', sorted(watch) or 'tutti',
          '| notify', [k for k, v in notify.items() if v], '| room', room,
          '| notify_devices', sorted(devices) or 'tutti', '| alias', len(aliases),
          '| debug', debug, flush=True)
    polls = 0

    while not stop_event.is_set():
        try:
            msg = inbox.get(timeout=1)
        except queue.Empty:
            continue
        try:
            if msg.topic == 'fritz.poll':
                polls += 1
                tracker.advance(msg.payload['ts'])
                if debug and polls % 20 == 1:
                    pending = [(d.mac, time.strftime('%H:%M:%S', time.localtime(d.left_at)))
                               for d in tracker.devices.values() if d.left_at is not None]
                    log('heartbeat n.', polls, '| watermark',
                        time.strftime('%H:%M:%S', time.localtime(tracker.watermark)),
                        '| in sospeso:', pending)
            elif msg.topic.startswith('fritz.wifi.'):
                tracker.on_event(msg.payload)
        except Exception:
            traceback.print_exc()   # il thread non deve morire per un evento anomalo


def main():
    import parse_events2
    p = argparse.ArgumentParser(description='Test offline del presence tracker su un file di log')
    p.add_argument('logfile')
    p.add_argument('--grace', type=int, default=90)
    p.add_argument('--newest-first', action='store_true',
                   help='il file ha l\'evento piu\' recente per primo (come il log del FritzBox)')
    args = p.parse_args()

    with open(args.logfile, encoding='utf-8') as fh:
        lines = fh.readlines()
    if args.newest_first:
        lines.reverse()

    events = []
    for line in lines:
        try:
            ev = parse_events2.parse_event(line)
        except (AssertionError, ValueError):
            continue
        if ev is not None and ev.is_valid:
            events.append(WifiEvent.from_parsed(ev, line.strip()))
    # Risoluzione del log = 1 s. A parita' di secondo: 'disconnected' prima di 'connected'
    # (riconnessione rapida; l'errore opposto genererebbe una falsa uscita).
    events.sort(key=lambda e: (e.ts, e.kind == 'connected'))

    tracker = PresenceTracker(lambda k, i: print(format_message(k, i)), grace=args.grace)
    for e in events:
        tracker.on_event(e)
    if events:
        tracker.advance(events[-1].ts + args.grace + 1)


if __name__ == '__main__':
    main()
