#!/usr/bin/env python3
"""
frame11 - offline PNL extractor for 802.11 captures (PCAP/PCAPNG)

Commands:
- frame11 pnl   <capture>   -> per-device PNL aggregation
- frame11 ssids <capture>   -> global SSID totals

Extras:
- ASCII banner at startup (can be disabled with --no-banner)
- Lightweight progress bar while parsing (can be disabled with --no-progress)
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, Optional, Iterable, Any, List

try:
    from scapy.all import PcapReader  # type: ignore
    from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Elt  # type: ignore
except Exception:
    print("[-] Scapy not available. Install with: pip install scapy", file=sys.stderr)
    raise


# ----------------------------
# Banner + Progress
# ----------------------------

BANNER = r"""
  ______                         __ __
 /_  __/______ ___ ___  ___ ____/ // /
  / / / __/ _ `__ `__ \/ -_) __/ _  /
 /_/ /_/  \_,_/ /_/ /_/\__/_/ /_//_/

      frame11 :: offline PNL extractor (802.11)
"""

def print_banner(enabled: bool) -> None:
    if enabled:
        # Print to stderr so stdout stays pipe-friendly
        sys.stderr.write(BANNER.strip("\n") + "\n\n")
        sys.stderr.flush()


class ProgressBar:
    """
    Lightweight progress bar using file position (tell) vs file size.
    - prints to stderr with carriage return
    - updates throttled to reduce overhead
    """
    def __init__(self, total_bytes: int, enabled: bool) -> None:
        self.total = max(1, int(total_bytes))
        self.enabled = enabled and sys.stderr.isatty()
        self.last_update = 0.0
        self.packets = 0

    def update(self, cur_bytes: int, packets_inc: int = 1) -> None:
        if not self.enabled:
            return

        self.packets += packets_inc
        now = time.monotonic()
        # Throttle updates to avoid slowing parsing
        if now - self.last_update < 0.15:
            return
        self.last_update = now

        pct = max(0.0, min(1.0, float(cur_bytes) / float(self.total)))
        width = 28
        filled = int(pct * width)
        bar = "#" * filled + "-" * (width - filled)
        msg = f"\r[+] parsing: [{bar}] {pct*100:5.1f}%  pkts={self.packets}"
        sys.stderr.write(msg)
        sys.stderr.flush()

    def finish(self) -> None:
        if not self.enabled:
            return
        sys.stderr.write("\r[+] parsing: done" + " " * 40 + "\n")
        sys.stderr.flush()


# ----------------------------
# Helpers (robust)
# ----------------------------

def iso_ts(ts) -> str:
    """
    Scapy pkt.time may be float, int, Decimal-like, EDecimal, etc.
    Normalize to float for datetime.fromtimestamp().
    """
    if ts is None:
        return dt.datetime.now(dt.timezone.utc).isoformat()

    try:
        ts_f = float(ts)
    except Exception:
        try:
            ts_f = float(str(ts))
        except Exception:
            return dt.datetime.now(dt.timezone.utc).isoformat()

    return dt.datetime.fromtimestamp(ts_f, tz=dt.timezone.utc).isoformat()


def mac_norm(mac: Optional[str]) -> str:
    return (mac or "").lower()


def hash_mac(mac: str, salt: str) -> str:
    # deterministic pseudonymization per-salt
    h = hashlib.blake2s(digest_size=10)
    h.update(salt.encode("utf-8", errors="ignore"))
    h.update(mac.encode("utf-8", errors="ignore"))
    return h.hexdigest()


def safe_ssid_bytes_to_str(b: bytes) -> str:
    # SSIDs can be non-UTF8; keep robust without crashing
    try:
        s = b.decode("utf-8", errors="strict")
    except Exception:
        s = b.decode("utf-8", errors="replace")
    return s.replace("\x00", "").strip()


def extract_probe_ssid(pkt) -> Optional[str]:
    """
    Returns SSID string if:
    - Probe Request
    - SSID element present
    - SSID element non-empty (directed probe)
    Otherwise returns None.
    """
    if not pkt.haslayer(Dot11) or not pkt.haslayer(Dot11ProbeReq):
        return None

    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if getattr(elt, "ID", None) == 0:  # SSID element
            info = getattr(elt, "info", b"") or b""
            if len(info) == 0:
                return None  # broadcast probe (no directed SSID)
            return safe_ssid_bytes_to_str(info)
        elt = elt.payload.getlayer(Dot11Elt)

    return None


def pkt_rssi(pkt) -> Optional[int]:
    """
    RSSI availability depends on capture headers (Radiotap/Prism/etc).
    We'll try common attributes Scapy may expose.
    """
    for attr in ("dBm_AntSignal", "dbm_antsignal", "Signal", "rssi"):
        if hasattr(pkt, attr):
            try:
                v = getattr(pkt, attr)
                if isinstance(v, (int, float)):
                    return int(v)
            except Exception:
                pass
    return None


def pkt_channel(pkt) -> Optional[int]:
    """
    Best-effort channel extraction:
    Try Radiotap freq -> map to channel for common 2.4GHz + basic 5GHz mapping.
    Often missing; keep optional.
    """
    freq = None
    for attr in ("ChannelFrequency", "channel_freq", "Channel", "freq"):
        if hasattr(pkt, attr):
            try:
                freq = getattr(pkt, attr)
            except Exception:
                pass

    if isinstance(freq, (int, float)):
        f = int(freq)
        # 2.4 GHz mapping
        if 2412 <= f <= 2472 and (f - 2407) % 5 == 0:
            return (f - 2407) // 5
        if f == 2484:
            return 14
        # Simple 5 GHz mapping (rough)
        if 5000 <= f <= 5900 and f % 5 == 0:
            ch = (f - 5000) // 5
            if 1 <= ch <= 200:
                return ch
    return None


# ----------------------------
# Data model
# ----------------------------

@dataclass
class PnlEvent:
    ts: str
    src: str          # raw addr2 (may be hidden if output via src_id)
    src_id: str       # pseudonymized by default
    ssid: str
    rssi: Optional[int]
    channel: Optional[int]


# ----------------------------
# Core logic
# ----------------------------

def iter_pnl_events(
    pcap_path: str,
    mac_salt: str,
    anonymize: bool,
    min_rssi: Optional[int],
    progress: ProgressBar,
) -> Iterable[PnlEvent]:
    total_bytes = os.path.getsize(pcap_path)

    with PcapReader(pcap_path) as pr:
        # Scapy keeps a file handle; use it for tell() when possible
        fh = getattr(pr, "f", None)

        for pkt in pr:
            # progress update (cheap; throttled)
            if fh is not None:
                try:
                    progress.update(fh.tell())
                except Exception:
                    pass

            ssid = extract_probe_ssid(pkt)
            if not ssid:
                continue

            dot11 = pkt.getlayer(Dot11)
            src = mac_norm(getattr(dot11, "addr2", None))
            if not src:
                continue

            rssi = pkt_rssi(pkt)
            if min_rssi is not None and rssi is not None and rssi < min_rssi:
                continue

            src_id = hash_mac(src, mac_salt) if anonymize else src
            ch = pkt_channel(pkt)

            yield PnlEvent(
                ts=iso_ts(getattr(pkt, "time", None)),
                src=src,
                src_id=src_id,
                ssid=ssid,
                rssi=rssi,
                channel=ch,
            )

    # Ensure bar ends cleanly
    progress.finish()


def build_pnl_report(events: Iterable[PnlEvent], min_hits: int) -> Dict[str, Any]:
    devices: Dict[str, Dict[str, Any]] = {}
    total_events = 0

    for ev in events:
        total_events += 1

        d = devices.setdefault(ev.src_id, {
            "ssids": {},
            "first_seen": ev.ts,
            "last_seen": ev.ts,
            "total_hits": 0,
        })

        d["last_seen"] = ev.ts
        d["total_hits"] += 1

        s = d["ssids"].setdefault(ev.ssid, {
            "hits": 0,
            "first_seen": ev.ts,
            "last_seen": ev.ts,
            "rssi_min": None,
            "rssi_max": None,
            "channels": {},
        })

        s["hits"] += 1
        s["last_seen"] = ev.ts

        if ev.rssi is not None:
            s["rssi_min"] = ev.rssi if s["rssi_min"] is None else min(s["rssi_min"], ev.rssi)
            s["rssi_max"] = ev.rssi if s["rssi_max"] is None else max(s["rssi_max"], ev.rssi)

        if ev.channel is not None:
            k = str(ev.channel)
            s["channels"][k] = s["channels"].get(k, 0) + 1

    # Filter by min_hits per SSID per device
    filtered_devices: Dict[str, Any] = {}
    for dev_id, info in devices.items():
        ssids = {k: v for k, v in info["ssids"].items() if v["hits"] >= min_hits}
        if not ssids:
            continue
        info2 = dict(info)
        info2["ssids"] = ssids
        filtered_devices[dev_id] = info2

    return {
        "tool": "frame11",
        "mode": "offline_pnl",
        "total_events": total_events,
        "devices": filtered_devices,
    }


def build_ssid_totals(events: Iterable[PnlEvent], min_hits: int) -> Dict[str, Any]:
    totals: Dict[str, Any] = {}
    total_events = 0

    for ev in events:
        total_events += 1
        s = totals.setdefault(ev.ssid, {
            "hits": 0,
            "devices": set(),
            "first_seen": ev.ts,
            "last_seen": ev.ts,
        })
        s["hits"] += 1
        s["last_seen"] = ev.ts
        s["devices"].add(ev.src_id)

    out: Dict[str, Any] = {}
    for ssid, info in totals.items():
        if info["hits"] < min_hits:
            continue
        out[ssid] = {
            "hits": info["hits"],
            "devices": len(info["devices"]),
            "first_seen": info["first_seen"],
            "last_seen": info["last_seen"],
        }

    return {
        "tool": "frame11",
        "mode": "ssid_totals",
        "total_events": total_events,
        "ssids": out,
    }


# ----------------------------
# CLI commands
# ----------------------------

def cmd_pnl(args: argparse.Namespace) -> int:
    if not os.path.exists(args.pcap):
        print(f"[-] File not found: {args.pcap}", file=sys.stderr)
        return 2

    print_banner(enabled=not args.no_banner)

    salt = args.salt or "frame11-default-salt"
    total_bytes = os.path.getsize(args.pcap)
    progress = ProgressBar(total_bytes=total_bytes, enabled=not args.no_progress)

    events_iter = iter_pnl_events(
        pcap_path=args.pcap,
        mac_salt=salt,
        anonymize=not args.no_anonymize,
        min_rssi=args.min_rssi,
        progress=progress,
    )

    events: List[PnlEvent] = []
    jsonl_fh = None
    try:
        if args.jsonl:
            jsonl_fh = open(args.jsonl, "w", encoding="utf-8")
        for ev in events_iter:
            events.append(ev)
            if jsonl_fh:
                jsonl_fh.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")
    finally:
        if jsonl_fh:
            jsonl_fh.close()

    report = build_pnl_report(events, min_hits=args.min_hits)

    dev_count = len(report["devices"])
    print(f"[+] frame11: events={report['total_events']} devices={dev_count} min_hits={args.min_hits}")

    if dev_count == 0:
        print("[!] No directed-probe SSIDs found (or all filtered).")
    else:
        top_devices = sorted(
            report["devices"].items(),
            key=lambda kv: kv[1].get("total_hits", 0),
            reverse=True
        )[:args.top]

        for dev_id, info in top_devices:
            ssids_sorted = sorted(info["ssids"].items(), key=lambda kv: kv[1]["hits"], reverse=True)
            ssid_list = ", ".join([f"{ssid}({st['hits']})" for ssid, st in ssids_sorted[:8]])
            print(f"  - dev {dev_id} hits={info['total_hits']} ssids={len(info['ssids'])} :: {ssid_list}")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"[+] Report written: {args.out}")

    return 0


def cmd_ssids(args: argparse.Namespace) -> int:
    if not os.path.exists(args.pcap):
        print(f"[-] File not found: {args.pcap}", file=sys.stderr)
        return 2

    print_banner(enabled=not args.no_banner)

    salt = args.salt or "frame11-default-salt"
    total_bytes = os.path.getsize(args.pcap)
    progress = ProgressBar(total_bytes=total_bytes, enabled=not args.no_progress)

    events_iter = iter_pnl_events(
        pcap_path=args.pcap,
        mac_salt=salt,
        anonymize=not args.no_anonymize,
        min_rssi=args.min_rssi,
        progress=progress,
    )

    events = list(events_iter)
    report = build_ssid_totals(events, min_hits=args.min_hits)
    ssids = report["ssids"]

    if not ssids:
        print("[!] No directed-probe SSIDs found (or all filtered).")
        return 0

    top = sorted(ssids.items(), key=lambda kv: kv[1]["hits"], reverse=True)[:args.top]
    print(f"[+] frame11 ssids: total_events={report['total_events']} unique_ssids={len(ssids)} min_hits={args.min_hits}")
    for ssid, info in top:
        print(f"  - {ssid} hits={info['hits']} devices={info['devices']}")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"[+] Report written: {args.out}")

    return 0


# ----------------------------
# CLI parser
# ----------------------------

def add_common_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--min-hits", type=int, default=2, help="minimum hits threshold (default: 2)")
    ap.add_argument("--top", type=int, default=10, help="show top N entries (default: 10)")
    ap.add_argument("--min-rssi", type=int, default=None, help="drop events with RSSI below this value (if available)")
    ap.add_argument("--salt", default=None, help="salt used for MAC pseudonymization (default: built-in)")
    ap.add_argument("--no-anonymize", action="store_true", help="do not pseudonymize MACs (prints raw addr2)")
    ap.add_argument("--no-banner", action="store_true", help="disable startup banner")
    ap.add_argument("--no-progress", action="store_true", help="disable progress bar")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="frame11",
        description="frame11 - offline PNL extractor (directed probe SSIDs) from 802.11 captures",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pnl = sub.add_parser("pnl", help="extract and aggregate PNL (per device) from a PCAP/PCAPNG")
    pnl.add_argument("pcap", help="input capture file (pcap/pcapng)")
    pnl.add_argument("-o", "--out", help="write JSON report to file")
    pnl.add_argument("--jsonl", help="write per-event JSONL to file")
    add_common_args(pnl)
    pnl.set_defaults(func=cmd_pnl)

    ss = sub.add_parser("ssids", help="show global SSID totals from directed probes")
    ss.add_argument("pcap", help="input capture file (pcap/pcapng)")
    ss.add_argument("-o", "--out", help="write JSON report to file")
    add_common_args(ss)
    ss.set_defaults(func=cmd_ssids)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
