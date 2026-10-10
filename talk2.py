#!/usr/bin/env python3
"""
Invia un messaggio a una conversazione Nextcloud Talk come BOT.

Testato contro l'API bot di Talk (spreed) su Nextcloud 34.x.

Variabili d'ambiente (oppure argomenti CLI):
  NC_URL          es. https://cloud.example.com
  NC_BOT_SECRET_FILE  percorso di un file contenente il segreto condiviso
                  (consigliato; chmod 600). In alternativa NC_BOT_SECRET.
                  Il segreto è quello usato in `talk:bot:install` (40-128 caratteri)
  NC_ROOM_TOKEN   token della conversazione (dall'URL: /call/<token>)

Uso:
  python3 talk2.py "Ciao dal bot!"
  python3 talk2.py "Risposta" --reply-to 123 --silent
  echo "testo da stdin" | python3 nc_bot_send.py -

Dipendenze: pip install requests
"""

import argparse
import hashlib
import hmac
import os
import secrets
import sys

import requests
from http import HTTPStatus

def load_secret(secret_file, secret_inline):
    """Legge il segreto da file (preferito) o, in fallback, dal valore diretto."""
    if secret_file:
        path = os.path.expanduser(secret_file)
        try:
            mode = os.stat(path).st_mode
            if mode & 0o077:
                print(f"Attenzione: {path} è leggibile da altri utenti "
                      f"(consigliato chmod 600).", file=sys.stderr)
            with open(path, "r", encoding="utf-8") as f:
                secret = f.read().strip()
        except OSError as e:
            sys.exit(f"Impossibile leggere il file del segreto: {e}")
        if not secret:
            sys.exit(f"Il file del segreto è vuoto: {path}")
        return secret
    return secret_inline



def send_message(base_url, user, secret, message, room,
                 reply_to=None, silent=False, reference_id=None,
                 verify_tls=True, timeout=15):

    # Inizializzazione della sessione HTTP con gli header obbligatori
    session = requests.Session()
    session.auth = (user, secret)
    session.headers.update({
        "OCS-APIRequest": "true",
        "Accept": "application/json"
    })

    chat_endpoint = f"{base_url}/ocs/v2.php/apps/spreed/api/v1/chat/{room}"

    payload = {
        "message": message,
        "replyTo": 0  # 0 indica un messaggio normale, non una risposta a un thread specifico
    }
    try:
        response = session.post(chat_endpoint, json=payload)
        if response.status_code in [HTTPStatus.OK, HTTPStatus.CREATED]:
            #print(f"Bot 🤖: Messaggio inviato con successo -> '{message}'")
            # Estraiamo l'ID del messaggio appena inviato dal bot per evitare di rileggerlo
            data = response.json()
            print(data)
            return data.get('ocs', {}).get('data', {}).get('id', 0)
        else:
            print(f"Errore durante l'invio del messaggio: {response.status_code} - {response.text}")
            return 0
    except Exception as e:
        print(f"Errore di connessione durante l'invio: {e}")
        return 0

def wait_message(base_url, user, secret, last_msg_id, room):
    #print("Bot 🤖: In attesa di una risposta o di nuovi messaggi...")

    # Inizializzazione della sessione HTTP con gli header obbligatori
    session = requests.Session()
    session.auth = (user, secret)
    session.headers.update({
        "OCS-APIRequest": "true",
        "Accept": "application/json"
    })

    chat_endpoint = f"{base_url}/ocs/v2.php/apps/spreed/api/v1/chat/{room}"

    # Empty message cannot be send
    message = ''

    while len(message) == 0:
        # Parametri di query per ottimizzare il polling
        params = {
            "lookIntoFuture": "1", # Chiede al server i messaggi più recenti
            "limit": "10"
        }
        if last_msg_id > 0:
            params["lastKnownMessageId"] = str(last_msg_id)

        try:
            response = session.get(chat_endpoint, params=params)
            print('response', response)
            print('response.status_code', response.status_code)
            print('len', len(message))
            if response.status_code == HTTPStatus.OK:
                data = response.json()
                print(data)
                messages = data.get('ocs', {}).get('data', [])

                for msg in messages:
                    msg_id = msg.get('id', 0)
                    autore = msg.get('actorDisplayName', 'Utente Sconosciuto')
                    message = msg.get('message', '')
                    tipo_attore = msg.get('actorType', '')

                    print('id', msg_id, 'author', autore, 'kind', tipo_attore)

                    # Elabora solo se il messaggio ha un ID superiore all'ultimo conosciuto
                    # ed evita di rispondere a se stesso (controllando che non sia un bot)
                    if msg_id > last_msg_id:
                        last_msg_id = msg_id
                        
                        if tipo_attore != "users" or msg.get('actorId') != user:
                            print(f"\nNuovo messaggio ricevuto! 📩")
                            print(f"Da: {autore} (ID Messaggio: {msg_id})")
                            print(f"Contenuto: {message}")

        except Exception as e:
            print(f"Errore durante il polling della chat: {e}")

    # Last message only
    return message
                            
def send_bot_message(base_url, room_token, bot_secret, message,
                     reply_to=None, silent=False, reference_id=None,
                     verify_tls=True, timeout=15):
    """Pubblica un messaggio nella chat come bot. Ritorna la risposta HTTP."""
    # Nonce casuale (almeno 32 caratteri) + firma HMAC-SHA256 di (random + message)
    random_hdr = secrets.token_hex(32)
    signature = hmac.new(
        bot_secret.encode("utf-8"),
        (random_hdr + message).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    url = f"{base_url.rstrip('/')}/ocs/v2.php/apps/spreed/api/v1/bot/{room_token}/message"

    headers = {
        "OCS-APIRequest": "true",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Nextcloud-Talk-Bot-Random": random_hdr,
        "X-Nextcloud-Talk-Bot-Signature": signature,
    }

    payload = {"message": message, "silent": silent}
    if reply_to is not None:
        payload["replyTo"] = reply_to
    # referenceId (sha256 hex, 64 caratteri) permette di correlare il messaggio
    payload["referenceId"] = reference_id or hashlib.sha256(
        (random_hdr + message).encode("utf-8")
    ).hexdigest()

    return requests.post(url, json=payload, headers=headers,
                         verify=verify_tls, timeout=timeout)

def main():
    p = argparse.ArgumentParser(description="Invia un messaggio Nextcloud Talk come bot")
    p.add_argument("message", help="Testo del messaggio ('-' per leggere da stdin)")
    p.add_argument("--url", default=os.environ.get("NC_URL"))
    p.add_argument("--room", default=os.environ.get("NC_ROOM_TOKEN"),
                   help="Token della conversazione")
    p.add_argument("--secret-file", default=os.environ.get("NC_BOT_SECRET_FILE"),
                   help="File contenente il segreto del bot")
    p.add_argument("--secret", default=os.environ.get("NC_BOT_SECRET"),
                   help="Segreto diretto (sconsigliato: visibile in `ps`)")
    p.add_argument("--reply-to", type=int, default=None,
                   help="ID del messaggio a cui rispondere")
    p.add_argument("--silent", action="store_true",
                   help="Nessuna notifica ai partecipanti")
    p.add_argument("--insecure", action="store_true",
                   help="Disabilita la verifica TLS (solo test, certificati self-signed)")
    args = p.parse_args()

    args.secret = load_secret(args.secret_file, args.secret)

    missing = [n for n, v in (("NC_URL", args.url), ("NC_ROOM_TOKEN", args.room),
                              ("NC_BOT_SECRET_FILE/NC_BOT_SECRET", args.secret)) if not v]
    if missing:
        sys.exit(f"Parametri mancanti: {', '.join(missing)}")

    message = sys.stdin.read().rstrip("\n") if args.message == "-" else args.message

    try:
        r = send_bot_message(args.url, args.room, args.secret, message,
                             reply_to=args.reply_to, silent=args.silent,
                             verify_tls=not args.insecure)
    except requests.RequestException as e:
        sys.exit(f"Errore di rete: {e}")

    if r.status_code == 201:
        print("Messaggio inviato (201 Created).")
        return

    errors = {
        400: "Richiesta non valida (messaggio vuoto/troppo lungo, o firma/nonce malformati).",
        401: "Firma non valida: controlla che il segreto coincida con quello di `talk:bot:install`.",
        404: "Bot non abilitato in questa conversazione, o token stanza errato.",
        413: "Messaggio troppo lungo (limite tipico 32000 caratteri).",
    }
    print(f"HTTP {r.status_code}: {errors.get(r.status_code, 'errore sconosciuto')}", file=sys.stderr)
    print(r.text[:500], file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
