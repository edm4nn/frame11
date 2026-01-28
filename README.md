frame11

frame11 è un tool CLI per Kali Linux dedicato all’analisi offline delle Preferred Network List (PNL) dei dispositivi Wi-Fi, estratte da Probe Request dirette (802.11) a partire da file PCAP / PCAPNG.

Il tool lavora in modo passivo, senza inviare pacchetti o interferire con le reti, ed è pensato per wireless reconnaissance, OSINT, analisi privacy e forense.

✨ Caratteristiche

Analisi offline di catture Wi-Fi (pcap, pcapng)

Estrazione directed probe SSIDs (PNL reali)

Aggregazione per dispositivo

Statistiche globali sugli SSID più ricercati

Output disponibili:

JSON strutturato (-o report.json)

JSONL evento-per-evento (--jsonl events.jsonl)

Pseudonimizzazione MAC deterministica tramite salt

Progress bar durante il parsing (senza rallentamenti)

Banner Kali-style con colori ANSI (disattivabile)

Totalmente CLI, pipe-safe e script-friendly

📦 Requisiti

Python 3.9+

Kali Linux (consigliato)

Scapy

Installazione dipendenze:

sudo apt update
sudo apt install -y python3-scapy

🔧 Installazione
git clone https://github.com/<tuo-username>/frame11.git
cd frame11
chmod +x frame11.py
sudo cp frame11.py /usr/local/bin/frame11


Verifica:

frame11 --help

🚀 Utilizzo
Analisi PNL per dispositivo
frame11 pnl capture.pcapng --min-hits 3 -o pnl_report.json


Esempio output:

[+] frame11: events=538 devices=27 min_hits=3
  - dev c00d370588d597f9a18 hits=96 ssids=1 :: IV_REP(96)
  - dev 6126614fc970d0654fd9 hits=48 ssids=1 :: RITEL(48)
  - dev 56986f2dd4e0385b7993 hits=46 ssids=4 :: FASTWEB-4SFJLY(14), Bbox-65A8B7B9(12)

Statistiche globali sugli SSID
frame11 ssids capture.pcapng --min-hits 5


Esempio output:

[+] frame11 ssids: total_events=538 unique_ssids=12 min_hits=5
  - TIM-92875269 hits=34 devices=6
  - FASTWEB-4SFJLY hits=14 devices=3

Output eventi raw (JSONL)
frame11 pnl capture.pcapng --jsonl pnl_events.jsonl


Formato di una riga:

{
  "ts": "2026-01-28T08:41:12+00:00",
  "src": "aa:bb:cc:dd:ee:ff",
  "src_id": "c00d370588d597f9a18",
  "ssid": "FASTWEB-4SFJLY"
}

⚙️ Opzioni CLI
Opzione	Descrizione
--min-hits N	Soglia minima di occorrenze per SSID
--top N	Mostra solo i primi N risultati
-o FILE	Scrive il report JSON
--jsonl FILE	Scrive eventi grezzi in JSONL
--salt STRING	Salt per la pseudonimizzazione MAC
--no-anonymize	Mostra MAC reali
--no-progress	Disabilita la progress bar
--no-banner	Disabilita il banner
--no-color	Disabilita colori ANSI
❌ Cosa non fa (per scelta)

Nessun attacco attivo

Nessuna deauth

Nessun cracking

Nessuna associazione AP ↔ STA

Nessuna GUI

frame11 è uno strumento di analisi passiva e forense.

🧠 Casi d’uso

Wireless reconnaissance

OSINT su dispositivi Wi-Fi

Analisi della privacy (leak di SSID)

Threat hunting wireless

Ricerca accademica

Supporto a framework Red Team

⚖️ Note legali ed etiche

Usare frame11 solo su catture autorizzate o in ambienti di test.
L’autore non è responsabile di utilizzi impropri o illegali.

🗺️ Roadmap (idee)

Export compatibile Kismet / WiGLE

Fingerprinting temporale delle PNL

Correlazione SSID ↔ posizione

Integrazione in framework Red Team

Packaging ufficiale per Kali Linux

📜 Licenza

MIT License

👤 Autore


Progetto focalizzato su PNL, privacy Wi-Fi e reconnaissance passiva.
