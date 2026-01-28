
# <img width="128" height="384" alt="frame11" src="https://github.com/user-attachments/assets/d5a37109-f9a3-40a7-9ece-37cb66b10fb9" />


frame11 è un tool CLI per Kali Linux dedicato all’analisi offline delle Preferred Network List (PNL) dei dispositivi Wi‑Fi, estratte da Probe Request dirette (802.11) a partire da file PCAP / PCAPNG.

---

## ✨ Caratteristiche

- Analisi offline di catture Wi‑Fi (pcap, pcapng)
- Estrazione di directed probe SSID (PNL reali)
- Aggregazione per dispositivo
- Statistiche globali sugli SSID più ricercati
- Output multipli: report JSON strutturato, JSONL evento‑per‑evento
- Pseudonimizzazione MAC deterministica tramite salt
- Progress bar durante il parsing (ottimizzata per non rallentare)
- Banner in stile Kali con colori ANSI (disattivabile)
- Totalmente CLI, pipe‑safe e script‑friendly

---

## 📦 Requisiti

- Python 3.9+
- Kali Linux (consigliato)
- Scapy

Installazione dipendenze:
```bash
sudo apt update
sudo apt install -y python3-scapy
```

---

## 🔧 Installazione

Clona il repository e installa lo script:
```bash
git clone https://github.com/<tuo-username>/frame11.git
cd frame11
chmod +x frame11.py
sudo cp frame11.py /usr/local/bin/frame11
```

Verifica:
```bash
frame11 --help
```

---

## 🚀 Utilizzo

Analisi PNL per dispositivo:
```bash
frame11 pnl capture.pcapng --min-hits 3 -o pnl_report.json
```

Esempio di output (sintesi):
```
[+] frame11: events=538 devices=27 min_hits=3
  - dev 56986f2dd4e0385b7993 hits=46 ssids=4 :: FASTWEB-8SKJHJ(14), TIM-68954(12)
```

Statistiche globali sugli SSID:
```bash
frame11 ssids capture.pcapng --min-hits 5
```

Esempio di output (sintesi):
```
[+] frame11 ssids: total_events=538 unique_ssids=12 min_hits=5
```

Output eventi raw (JSONL):
```bash
frame11 pnl capture.pcapng --jsonl pnl_events.jsonl
```

Formato di una riga JSONL:
```json
{
  "ts": "2026-01-28T08:41:12+00:00",
  "src": "aa:bb:cc:dd:ee:ff",
  "src_id": "c00d370588d597f9a18",
  "ssid": "FASTWEB-8SKJHJ"
}
```

---

## ⚙️ Opzioni CLI

Opzione | Descrizione
---|---
`--min-hits N` | Soglia minima di occorrenze per SSID
`--top N` | Mostra solo i primi N risultati
`-o FILE` | Scrive il report JSON
`--jsonl FILE` | Scrive eventi grezzi in JSONL
`--salt STRING` | Salt per la pseudonimizzazione MAC
`--no-anonymize` | Mostra MAC reali
`--no-progress` | Disabilita la progress bar
`--no-banner` | Disabilita il banner
`--no-color` | Disabilita i colori ANSI

---

## ❌ Cosa non fa 

- Nessun attacco attivo
- Nessuna deauth
- Nessun cracking
- Nessuna associazione AP ↔ STA
- Nessuna GUI

frame11 è uno strumento di analisi passiva e forense.

---

## 🧠 Casi d’uso

- Wireless reconnaissance
- OSINT su dispositivi Wi‑Fi
- Analisi della privacy (leak di SSID)
- Threat hunting wireless
- Ricerca accademica
- Supporto a framework Red Team

---

## ⚖️ Note legali ed etiche

Usare frame11 solo su catture autorizzate o in ambienti di test. L’autore non è responsabile di utilizzi impropri o illegali.

---

## 📜 Licenza

MIT License
