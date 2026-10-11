"""Annota una riga di log con hostname e ultimo IP dei MAC che contiene."""
import re
from pathlib import Path


class AnnotatoreMac:
    """Associa i MAC trovati in una riga di testo a hostname e ultimo IP letti da un TSV.

    Il TSV ha una riga per dispositivo: mac <tab> hostname <tab> ip.
    Il caricamento avviene alla creazione dell'oggetto (o con ricarica()), non all'importazione.
    """

    MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")
    NA = "---"  # valore usato nel TSV quando hostname o IP mancano

    def __init__(self, percorso):
        self.percorso = Path(percorso)
        self.db = {}
        self.ricarica()

    @staticmethod
    def normalizza_mac(mac: str) -> str:
        """'9a-58-f4-b5-99-a9' -> '9A:58:F4:B5:99:A9'"""
        return mac.replace("-", ":").upper()

    def ricarica(self) -> None:
        """(Ri)legge il TSV e sostituisce il contenuto di self.db: {mac: (hostname, ip)}."""
        db = {}
        with open(self.percorso, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                mac, hostname, ip = line.split("\t")
                db[self.normalizza_mac(mac)] = (hostname, ip)
        self.db = db

    def estrai_mac(self, riga: str) -> list:
        """MAC presenti nella riga: normalizzati, senza duplicati, nell'ordine di comparsa."""
        trovati = []
        for m in self.MAC_RE.findall(riga):
            m = self.normalizza_mac(m)
            if m not in trovati:
                trovati.append(m)
        return trovati

    def nota_mac(self, mac: str) -> str:
        """Testo della nota per un singolo MAC (già normalizzato)."""
        if mac not in self.db:
            return "NON PRESENTE nell'elenco!!!"
        hostname, ip = self.db[mac]
        nome = hostname if hostname != self.NA else "NOME SCONOSCIUTO!!!"
        ip_txt = f"ultimo IP {ip}" if ip != self.NA else "nessun IP registrato"
        return f"{nome}, {ip_txt}"

    def annota(self, riga: str) -> str:
        """Restituisce la riga con in coda una nota per ogni MAC trovato."""
        note = [self.nota_mac(mac) for mac in self.estrai_mac(riga)]
        if not note:
            return riga
        return f"{riga}  [NOTA: {'; '.join(note)}]"


if __name__ == "__main__":
    annotatore = AnnotatoreMac(Path(__file__).with_name("mac_hostname_ip.tsv"))
    print(annotatore.annota("Dispositivo wireless connesso (5 GHz), 866 Mbit/s, MAC 9a:58:f4:b5:99:a9."))
    print(annotatore.annota("Dispositivo wireless disconnesso, MAC 82:A2:23:5D:38:F4"))
    print(annotatore.annota("Dispositivo wireless connesso, MAC AA:BB:CC:DD:EE:FF"))
    print(annotatore.annota("Riga senza indirizzi MAC"))
