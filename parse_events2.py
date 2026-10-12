import sys
import re
import datetime
import types

def dict_to_struct(d):
    # The ** unpacking operator turns the dict keys into keyword arguments
    return types.SimpleNamespace(**d)

def parse_event(line, do_log=False):
    # Regex per intercettare la data a inizio riga (es. 28.09.26 14:42:55  |)
    # Permette spazi variabili prima del pipe
    row_pattern = re.compile(r"^(\d{2}\.\d{2}\.\d{2}\s+\d{2}:\d{2}:\d{2})\s*(.*)")
    
    line = line.strip().rstrip('.')
    match = row_pattern.match(line.replace(' | ', ''))

    if do_log:
        print('parse_event:', line)

    if not match:
        return None
    
    date_str, event_content = match.groups()
    ts = datetime.datetime.strptime(date_str, '%d.%m.%y %H:%M:%S')
    #print('---------------------')
    #print(date_str, event_content)
    
    # Controllo validità minimo: servono almeno i campi base
    # Struttura attesa: Ragione (connesso/disconnesso + GHz), Velocità, Hostname, IP, MAC (totale 5 campi)
    pos = event_content.find('GHz),')
    is_valid = pos != -1

    if is_valid:
        # Skip GHz),
        pos += 5

        # Splitta l'evento sulle virgole
        parts = [event_content[:pos-1].strip()] + [p.strip() for p in event_content[pos:].split(',')]
        #print(parts)

        reason = parts[0] #.lower()
        #print('reason', reason)
        if ' connesso ' in reason:
            assert(len(parts) == 5)
            kind = 'connected '
            speed, hostname, ip, mac = parts[1:]
        elif ' disconnesso ' in reason:
            assert(len(parts) == 4)
            kind = 'disconnect'
            hostname, ip, mac = parts[1:]
            speed = '---'
        else:
            is_valid = False

        if is_valid:
            assert(ip.startswith('IP '))
            assert(mac.startswith('MAC '))
            ip = ip[3:]
            mac = mac[4:]
            m = re.search(r"\(([0-9,]+\s*GHz)\)$", reason)
            if m is None:
                is_valid = False
            else:
                carrier, = m.groups()
                #print('carrier', carrier)
                #print('is_valid', is_valid)
    
    if is_valid:
        ret = {
            "status": "VALID",
            "is_valid": True,
            "date": str(ts),
            "reason": parts[0],
            'kind': kind,
            "carrier": carrier,
            "speed": speed,
            "hostname": hostname,
            "ip": ip,
            "mac": mac
        }
    else:
        ret = {
            "status": "INVALID",
            "is_valid": False,
            "date": str(ts),
            "raw_event": event_content
        }

    return dict_to_struct(ret)

def process_file_generator(file_path, do_log=False):
    # Regex per intercettare la data a inizio riga (es. 28.09.26 14:42:55  |)
    # Permette spazi variabili prima del pipe
    row_pattern = re.compile(r"^(\d{2}\.\d{2}\.\d{2}\s+\d{2}:\d{2}:\d{2})\s*\|\s*(.*)")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                event = parse_event(line)
                if event is None:
                    continue

                event.line_num = line_num
                yield event
    except FileNotFoundError:
        print(f"Errore: Il file '{file_path}' non esiste.", file=sys.stderr)
    except PermissionError:
        print(f"Errore: Permessi insufficienti per leggere '{file_path}'.", file=sys.stderr)

def main():
    if len(sys.argv) < 2:
        print("Uso: python parse_events.py <nome_file.md>")
        sys.exit(1)
        
    show_invalid_only  = '--show-invalid-only' in sys.argv
    show_filename_only = '--show-filename-only' in sys.argv
    do_log = '--do-log' in sys.argv

    #print(f"Inizio analisi del file: {file_path}\n" + "-"*50)
    for arg in sys.argv[1:]:
        if not arg.startswith('--'):
            file_path = arg
    
            if show_invalid_only or show_filename_only or do_log:
                print(file_path)

            for event in process_file_generator(file_path, do_log=do_log):
                if event.is_valid:
                    if not show_invalid_only and not show_filename_only:
                        print("\t".join([event.date, event.kind, event.carrier, event.speed, event.mac, event.ip, event.hostname]))
                else:
                    msg = f'UNKNOWN FORMAT at line {event.line}: {event.date} | {event.raw_event}'
                    if show_invalid_only:
                        print(msg)
                    else:
                        assert(False)
#                assert(event.status"] == "VALID"), f'Not known format at line {event.line"]}: {event.raw_event"]}'
#                    continue
#                    print(f"[RIGA {entry['line']}] VALIDO - Data: {entry['date']}")
#                    print(f"  -> Ragione:   {entry['reason']}")
#                    print(f"  -> Portante:  {entry['carrier']}")
#                    print(f"  -> Velocità:  {entry['speed']}")
#                    print(f"  -> Hostname:  {entry['hostname']}")
#                    print(f"  -> IP / MAC:  {entry['ip']} / {entry['mac']}\n")
#                else:
#                    print(f"[RIGA {entry['line']}] NON CONFORME - Data: {entry['date']}")
#                    print(f"  -> Testo:     {entry['raw_event']}\n")

def t1():
    s = "12.10.26 14:00:36 Il dispositivo wireless si è disconnesso dall'accesso ospite (5 GHz), ---, IP ---, MAC 9A:58:F4:B5:99:A9."
    ev = parse_event(s, do_log=True)
    print(ev)

if __name__ == '__main__':
    #main()
    t1()
