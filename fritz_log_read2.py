import os, sys
import re
import time
import datetime
import getpass
import xml.etree.ElementTree as ET
import fritzconnection
import talk2
import configparser
import annota_mac

config = configparser.ConfigParser()
config.read('lotu.ini')

# Fritz.box parameters
FB_IP = config['fritzbox']['FB_IP']
USER = config['fritzbox']['USER']
POLL_INTERVAL = config['fritzbox'].getint('POLL_INTERVAL')
print('POLL_INTERVAL', POLL_INTERVAL)
OUTPUT_XML = config['fritzbox']['OUTPUT_XML']

# Talk2 parameters
NC_URL= config['talk']['NC_URL']
ROOM_TOKEN= config['talk']['ROOM_TOKEN']
# Bot
#SECRET = talk2.load_secret(os.path.expanduser("~/radarbot.token"), None)
# User bot
BOT_USER= config['talk']['BOT_USER']
BOT_SECRET= config['talk']['BOT_SECRET']
PASSWORD= config['talk']['PASSWORD']

# Scripts parameters
do_read_events = True

if not do_read_events:
    # Reduce the frequency when in dry run mode.
    POLL_INTERVAL=60

conn = None
current_logs = None
annotator = None

# Read the mac <-> hostname <-> ip expected.
try:
    annotator = annota_mac.AnnotatoreMac("mac_hostname_ip.tsv")
except FileNotFoundError as e:
    print(f"Errore: il file '{e.filename}' non è stato trovato.")
    print('Continuo senza note')

FRITZ_DATETIME_FMT='%d.%m.%y %H:%M:%S'
RADAR_DATETIME_FMT='%Y:%m.%d %H:%M:%S'

# Test send / recv message to / from the chat.
#msg_id  = talk2.send_message(NC_URL, BOT_USER, BOT_SECRET, 'Inserisci OTP per autenticazione...', ROOM_TOKEN)
#print('1) Msg posted id', msg_id)
#message = talk2.wait_message(NC_URL, BOT_USER, BOT_SECRET, msg_id, ROOM_TOKEN)
#print('2) Message read', message)
#sys.exit(0)

def notifica_bot(testo, room=ROOM_TOKEN, reply_to=None, silent=False):
    r = talk2.send_bot_message(NC_URL, room, BOT_SECRET, testo,
                         reply_to=reply_to, silent=silent)
    if r.status_code != 201:
        raise RuntimeError(f"Invio fallito: HTTP {r.status_code} - {r.text[:200]}")

def notifica(testo, room=ROOM_TOKEN, reply_to=None, silent=False):
    return talk2.send_message(NC_URL, BOT_USER, BOT_SECRET, testo, ROOM_TOKEN,
                              reply_to=reply_to, silent=silent)

def log(*args, **kwargs):
    #ts = datetime.datetime.now().strftime('%d.%b %Y %H:%M:%S')
    ts = datetime.datetime.now().strftime(RADAR_DATETIME_FMT)
    print(ts, *args, **kwargs)
    sys.stdout.flush()

def parse_riga_log(line):
    """
    Analizza la riga del log del FRITZ!Box.
    Restituisce una tupla: (datetime_oggetto, stringa_originale_ordinabile, gruppo, messaggio_pulito)
    """
    # Regex robusta per catturare: 
    # 1. Data e ora (GG.MM.AA HH:MM:SS)
    # 2. Tutto il resto del testo
    match = re.match(r"^(\d{2}\.\d{2}\.\d{2}\s+\d{2}:\d{2}:\d{2})\s+(.*)$", line)
    
    # In caso di errore, sia del formato generale che del data&time, usa il dt di sistema
    dt = datetime.datetime.now().strftime(RADAR_DATETIME_FMT)

    if match:
        data_str = match.group(1)
        testo_residuo = match.group(2)
        
        # Converte in oggetto datetime per l'ordinamento corretto
        #try:
        dt = datetime.datetime.strptime(data_str, FRITZ_DATETIME_FMT)
        #except ValueError:
        #    pass
    else:
        # Se la riga non ha un timestamp standard (es. righe di boot o anomalie)
        return (line, dt, "FORMATUNKNOWN", line)

    # Identifica il gruppo analizzando il testo residuo
    if any(k in testo_residuo for k in ["WLAN", "Wi-Fi", "registrato", "frequenza", "dispositivo wireless"]):
        gruppo = "WI-FI"
    elif any(k in testo_residuo for k in ["Internet", "DSL", "PPPoE", "IP", "DNS", "IPv6"]):
        gruppo = "INTERNET"
    elif any(k in testo_residuo for k in ["Telefon", "voip", "Numero", "chiamata"]):
        gruppo = "TELEFONIA"
    elif any(k in testo_residuo for k in ["utente", "aggiornamento", "ora", "riavvio", "energia"]):
        gruppo = "SISTEMA"
    else:
        gruppo = "GENERALE"

    return (line, dt, gruppo, testo_residuo)

def get_remote_logs1(conn):
    """Recupera i log dal FRITZ!Box e restituisce una lista di righe."""
    try:
        result = conn.call_action("DeviceInfo1", "GetDeviceLog")
        log_text = result.get("NewDeviceLog", "")
        # Pulisce il testo e lo divide in righe, escludendo stringhe vuote
        #return sorted([parse_riga_log(line.strip())[0] for line in log_text.splitlines() if line.strip()], key=lambda x: x)
        return [line.strip() for line in log_text.splitlines() if line.strip()]
    except Exception as e:
        print(f"\n[Errore durante il recupero dei log: {e}]", file=sys.stderr)
        return []

'''
<Event>
<id>22</id>
<group>net</group>
<date>02.10.26</date>
<time>12:17:31</time>
<msg>La connessione Internet è stata stabilita. Indirizzo IP: 100.112.233.34, server DNS: 195.234.128.139 e 217.68.162.53, gateway: 100.112.232.1</msg>
</Event>
'''

def get_remote_logs(conn):
    """
    Sfrutta la chiamata nativa AVM per ottenere il file XML 
    completo di tutti i log, aggirando il troncamento di GetDeviceLog.
    """
    try:
        # 1. Richiede il percorso del file di log esteso
        result = conn.call_action('DeviceInfo1', 'X_AVM-DE_GetDeviceLogPath')
        path = result.get("NewDeviceLogPath")
        print(result)
        
        if not path:
            print("Funzionalità estesa non supportata dal tuo firmware. Uso fallback...")
            log_text = conn.call_action("DeviceInfo1", "GetDeviceLog").get("NewDeviceLog", "")
            return [line.strip() for line in log_text.splitlines() if line.strip()]
        
        # 2. Genera l'URL interno ed esegue il download dell'XML autenticato
        url = f"{conn.address}:{conn.port}{path}"
        response = conn.session.get(f"{conn.address}:{conn.port}{path}", verify=False)
        response.raise_for_status()

        with open(OUTPUT_XML, "wb") as f:
            f.write(response.content)

#        xml_root = fritzconnection.core.utils.get_xml_root(url, session=conn.session)
        xml_root = ET.fromstring(response.content)
        
        # 3. Estrae e ricostruisce i log riga per riga dal documento XML
        righe_complete = []
        for event in xml_root.findall('.//Event'):
            #print('EVENT FOUND', event.text)
            date = event.find('date').text if event.find('date') is not None else ""
            time_str = event.find('time').text if event.find('time') is not None else ""
            msg = event.find('msg').text if event.find('msg') is not None else ""
            #print('EXTRACT', date, time_str, msg)
            
            if msg:
                righe_complete.append(f"{date} {time_str} {msg}".strip())
                
        # Unisce le righe ricreando il blocco di testo 'log_text' per le tue funzioni
        #print('RET', righe_complete)
        return righe_complete
        
    except Exception as e:
        print(f"Errore nel recupero dei log estesi: {e}")
        return ""

log('home_reader', '--- Inizio monitoraggio log ---')

while True:
    try:
        if conn is None:
            ts = datetime.datetime.now().strftime(RADAR_DATETIME_FMT)
            if not do_read_events:
                log('home_reader', 'Skipping event read...')
                notifica(f'Skipping event read. Now is {ts}')
            else:
                msg_id = talk2.send_message(NC_URL, BOT_USER, BOT_SECRET, f"{ts}\nHello from Raspi5 :):", ROOM_TOKEN)
                log('BOOT.1 Welcome msg posted, id', msg_id)
                #message = talk2.wait_message(NC_URL, BOT_USER, BOT_SECRET, msg_id, ROOM_TOKEN)
                #log('BOOT.2 Message read from user:', message, 'len', len(message))

                log('home_reader', 'Connecting...')
                notifica('Connecting...')
                conn = fritzconnection.FritzConnection(address=FB_IP, user=USER, password=PASSWORD, use_tls=True)
                # Al primo avvio, memorizza lo stato attuale per non ristampare l'intero storico
                historical_logs = set(get_remote_logs(conn))
                for entry in historical_logs:
                    line, dt, gruppo, msg = parse_riga_log(entry)
                    print(line) #, dt, f'[{gruppo}]', msg)
                    #notifica(line)
                    sys.stdout.flush()
                log('home_reader', 'Initial log read successfully!')
                notifica('Initial log read successfully!')

    except Exception as e:
        log('home_reader', f'home_reader Errore di connessione iniziale: {e}, retry', file=sys.stderr)
        pass

    try:
        time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        log("\nhome_reader: Monitoraggio interrotto dall'utente.")
        sys.exit(0)

    if do_read_events and (conn is not None):
        current_logs = get_remote_logs(conn)
        
        # Identifica solo le righe nuove che non erano presenti nel set precedente
        new_entries = [line for line in current_logs if line not in historical_logs]
        
        if new_entries:
            for entry in new_entries:
                line, dt, gruppo, msg = parse_riga_log(entry)
                print(line) #dt, f'[{gruppo}]', msg)
                if annotator is None:
                    line = line + ' [DB not found!!!]'
                else:
                    line = annotator.annota(line)
                notifica(line)
                sys.stdout.flush() # Forza la scrittura immediata sul terminale
            
            # Aggiorna il set storico con le nuove righe
            historical_logs |= set(new_entries)
