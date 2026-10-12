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
        """(Ri)legge il TSV e sostituisce il contenuto di self.db: {mac: (hostname, ip)}.

        Il caricamento è rigoroso: ogni riga deve avere esattamente tre campi
        (mac, hostname, ip) e nessuno può essere vuoto o '---'. Le righe non valide
        vengono raccolte e segnalate tutte insieme in un unico ValueError;
        in tal caso self.db resta com'era prima della chiamata.
        """
        db = {}
        errori = []
        with open(self.percorso, encoding="utf-8") as f:
            for numero, line in enumerate(f, start=1):
                line = line.rstrip("\n")
                if not line:
                    continue
                campi = line.split("\t")
                if len(campi) != 3:
                    errori.append(f"riga {numero}: attesi 3 campi separati da tab, trovati {len(campi)}")
                    continue
                mac, hostname, ip = (c.strip() for c in campi)
                mancanti = [nome for nome, valore in (("mac", mac), ("hostname", hostname), ("ip", ip))
                            if valore in ("", self.NA)]
                if mancanti:
                    errori.append(f"riga {numero} ({mac or '?'}): "
                                  f"{', '.join(mancanti)} mancante/i")
                    continue
                db[self.normalizza_mac(mac)] = (hostname, ip)
        if errori:
            raise ValueError(f"{self.percorso}: {len(errori)} righe non valide:\n  " + "\n  ".join(errori))
        self.db = db

    def estrai_mac(self, riga: str) -> list:
        """MAC presenti nella riga: normalizzati, senza duplicati, nell'ordine di comparsa."""
        trovati = []
        for m in self.MAC_RE.findall(riga):
            m = self.normalizza_mac(m)
            if m not in trovati:
                trovati.append(m)
        return trovati

    def cerca(self, mac: str):
        """Dato un MAC (in qualsiasi formato: maiuscolo/minuscolo, ':' o '-') restituisce (hostname, ip).

        Se il MAC non è nell'elenco restituisce None. Grazie al caricamento rigoroso,
        hostname e ip della tupla sono sempre stringhe valide.
        """
        return self.db.get(self.normalizza_mac(mac))

    def nota_mac(self, mac: str) -> str:
        """Testo della nota per un singolo MAC."""
        mac = self.normalizza_mac(mac)
        risultato = self.cerca(mac)
        if risultato is None:
            return f"{mac}: non presente nell'elenco"
        hostname, ip = risultato
        return f"{mac}: {hostname}, ultimo IP {ip}"

    def _mancante(self, valore) -> bool:
        """True se il valore in ingresso è assente: None, stringa vuota o '---'."""
        return valore is None or str(valore).strip() in ("", self.NA)

    def confronta(self, mac: str, hostname=None, ip=None, do_log=False) -> str:
        """Confronta hostname e ip osservati con quelli dell'elenco e descrive solo le differenze.

        hostname e ip possono essere None, '' o '---': significa "dato non disponibile",
        quindi quel campo non viene confrontato (non può contraddire l'elenco).

        Restituisce:
        - '' se non c'è nessuna differenza (o non c'è nulla da confrontare);
        - una nota con i soli campi diversi, ad es.
          '9A:...: ip diverso (elenco: 192.168.189.7, trovato: 192.168.189.9)';
        - una nota 'non presente nell'elenco' se il MAC è sconosciuto.
        """
        if do_log: print('confronta', mac, hostname, ip)
        mac = self.normalizza_mac(mac)
        voce = self.cerca(mac)
        if voce is None:
            if do_log: print(f"{mac}: non presente nell'elenco")
            return f"{mac}: non presente nell'elenco"
        hostname_db, ip_db = voce
        differenze = []
        for nome, trovato, atteso in (("hostname", hostname, hostname_db), ("ip", ip, ip_db)):
#            if self._mancante(trovato):
#                if do_log: print(f"mancante: {trovato}")
#                continue
            trovato = str(trovato).strip()
            if trovato != atteso:
                if do_log: print(f"{nome} diverso (elenco: {atteso}, trovato: {trovato})")
                #differenze.append(f"{nome} diverso (elenco: {atteso}, trovato: {trovato})")
                differenze.append(f"{nome} {atteso}")
        if not differenze:
            if do_log: print('No differences :)')
            return ""
        if do_log: print("; ".join(differenze))
        #return f"{mac}: " + "; ".join(differenze)
        return "; ".join(differenze)

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
    annotatore.confronta('9A:58:F4:B5:99:A9', '---', '---', do_log=True)
