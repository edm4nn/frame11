#!/usr/bin/env python3
"""
frame11 - offline PNL extractor (directed probe SSIDs) from 802.11 captures (PCAP/PCAPNG)

Commands:
- frame11 pnl   <capture>  -> per-device PNL aggregation
- frame11 ssids <capture>  -> global SSID totals

Outputs:
- -o/--out : JSON report
- --jsonl  : per-event JSONL stream (one event per line)

Extras:
- Clean Kali-style banner (ANSI 256-color) to stderr (disable with --no-banner/--no-color)
- Lightweight progress bar while parsing (disable with --no-progress)
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
from typing import Dict, Optional, Iterable, Any, List, Tuple

try:
    from scapy.all import PcapReader  # type: ignore
    from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Elt  # type: ignore
except Exception:
    print("[-] Scapy not available. Install with: pip install scapy", file=sys.stderr)
    raise


# ============================
# Banner (Kali-pro)
# ============================

BANNER = r"""
███████╗██████╗  █████╗ ███╗   ███╗███████╗ ██╗ ██╗
██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝███║███║
█████╗  ██████╔╝███████║██╔████╔██║█████╗  ╚██║╚██║
██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝   ██║ ██║
██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗ ██║ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚═╝ ╚═╝
        802.11 PNL extractor (offline)
"""

def _c256(n: int) -> str:
    return f"\x1b[38;5;{n}m"

def _reset() -> str:
    return "\x1b[0m"

def _bold() -> str:
    return "\x1b[1m"

def _dim() -> str:
    return "\x1b[2m"

def colorize_banner(text: str) -> str:
    """
    - logo: neon green (46)
    - subtitle: dim cyan (51)
    """
    lines = text.strip("\n").splitlines()
    out: List[str] = []
    for line in lines:
        if not line.strip():
            out.append(line)
            continue
        low = line.lower()
        if "802.11" in low or "extractor" in low or "offline" in low:
            out.append(_dim() + _c256(51) + line + _reset())
        else:
            out.append(_bold() + _c256(46) + line + _reset())
    return "\n".join(out)

def print_banner(enabled: bool, color: bool) -> None:
    if not enabled:
        return
    use_color = color and sys.stderr.isatty()
    if use_color:
        sys.stderr.write(colorize_banner(BANNER) + "\n")
        sys.stderr.write(_dim() + _c256(244) + "[*] loading capture engine... done\n\n" + _reset())
    else:
        sys.stderr.write(BANNER.strip("\n") + "\n\n")
    sys.stderr.flush()


# ============================
# Progress bar (fast)
# ============================

class ProgressBar:
    """
    Minimal overhead progress bar:
    - percent based on file offset / file size (tell vs size)
    - throttled updates (default 0.15s)
    """
    def __init__(self, total_bytes: int, enabled: bool, throttle_s: float = 0.15) -> None:
        self.total = max(1, int(total_bytes))
        self.enabled = enabled and sys.stderr.isatty()
        self.throttle_s = throttle_s
        self.last_update = 0.0
        self.packets = 0

    def update(self, cur_bytes: int) -> None:
        if not self.enabled:
            return
        self.packets += 1

        now = time.monotonic()
        if now - self.last_update < self.throttle_s:
            return
        self.last_update = now

        pct = max(0.0, min(1.0, float(cur_bytes) / float(self.total)))
        width = 28
        filled = int(pct * width)
        bar = "#" * filled + "-" * (width - filled)
        sys.stderr.write(f"\r[+] parsing: [{bar}] {pct*100:5.1f}%  pkts={self.packets}")
        sys.stderr.flush()

    def finish(self) -> None:
        if not self.enabled:
            return
        sys.stderr.write("\r[+] parsing: done" + " " * 40 + "\n")
        sys.stderr.flush()


# ============================
# Helpers
# ============================

def iso_ts(ts: Any) -> str:
    """
    pkt.time can be float, int, Decimal/EDecimal-like.
    Normalize via float() (fallback: float(str(ts))).
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
    h = hashlib.blake2s(digest_size=10)
    h.update(salt.encode("utf-8", errors="ignore"))
    h.update(mac.encode("utf-8", errors="ignore"))
    return h.hexdigest()

def safe_ssid_bytes_to_str(b: bytes) -> str:
    s = b.decode("utf-8", errors="replace")
    return s.replace("\x00", "").strip()

def extract_probe_ssid(pkt) -> Optional[str]:
    """
    Returns SSID if:
    - Dot11 + ProbeReq
    - SSID IE present and non-empty (directed probe)
    """
    if not pkt.haslayer(Dot11) or not pkt.haslayer(Dot11ProbeReq):
        return None

    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if getattr(elt, "ID", None) == 0:
            info = getattr(elt, "info", b"") or b""
            if not info:
                return None
            return safe_ssid_bytes_to_str(info)
        elt = elt.payload.getlayer(Dot11Elt)
    return None


# ============================
# Data model
# ============================

@dataclass
class PnlEvent:
    ts: str
    src: str          # raw addr2 (STA)
    src_id: str       # pseudonymized unless --no-anonymize
    ssid: str


# ============================
# Core parsing
# ============================

def iter_pnl_events(
    pcap_path: str,
    salt: str,
    anonymize: bool,
    progress: ProgressBar,
) -> Iterable[PnlEvent]:

    with PcapReader(pcap_path) as pr:
        fh = getattr(pr, "f", None)

        for pkt in pr:
            if fh is not None:
                try:
                    progress.update(fh.tell())
                except Exception:
                    pass

            ssid = extract_probe_ssid(pkt)
            if not ssid:
                continue

            dot11 = pkt.getlayer(Dot11)
            if dot11 is None:
                continue

            src = mac_norm(getattr(dot11, "addr2", None))
            if not src:
                continue

            src_id = hash_mac(src, salt) if anonymize else src

            yield PnlEvent(
                ts=iso_ts(getattr(pkt, "time", None)),
                src=src,
                src_id=src_id,
                ssid=ssid,
            )

    progress.finish()


# ============================
# Reports
# ============================

def build_pnl_report(events: Iterable[PnlEvent], min_hits: int) -> Dict[str, Any]:
    devices: Dict[str, Dict[str, Any]] = {}
    total_events = 0

    for ev in events:
        total_events += 1
        d = devices.setdefault(ev.src_id, {
            "first_seen": ev.ts,
            "last_seen": ev.ts,
            "total_hits": 0,
            "ssids": {},  # ssid -> hits
        })
        d["last_seen"] = ev.ts
        d["total_hits"] += 1
        d["ssids"][ev.ssid] = d["ssids"].get(ev.ssid, 0) + 1

    # filter by min_hits per ssid
    filtered: Dict[str, Any] = {}
    for dev_id, info in devices.items():
        ssids = {s: h for s, h in info["ssids"].items() if h >= min_hits}
        if not ssids:
            continue
        info2 = dict(info)
        info2["ssids"] = ssids
        filtered[dev_id] = info2

    return {
        "tool": "frame11",
        "mode": "offline_pnl",
        "total_events": total_events,
        "min_hits": min_hits,
        "devices": filtered,
    }

def build_ssid_totals(events: Iterable[PnlEvent], min_hits: int) -> Dict[str, Any]:
    totals: Dict[str, Dict[str, Any]] = {}
    total_events = 0

    for ev in events:
        total_events += 1
        t = totals.setdefault(ev.ssid, {
            "hits": 0,
            "devices": set(),
            "first_seen": ev.ts,
            "last_seen": ev.ts,
        })
        t["hits"] += 1
        t["last_seen"] = ev.ts
        t["devices"].add(ev.src_id)

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
        "min_hits": min_hits,
        "ssids": out,
    }


# ============================
# CLI
# ============================

def cmd_pnl(args: argparse.Namespace) -> int:
    if not os.path.exists(args.pcap):
        print(f"[-] File not found: {args.pcap}", file=sys.stderr)
        return 2

    print_banner(enabled=not args.no_banner, color=not args.no_color)

    salt = args.salt or "frame11-default-salt"
    progress = ProgressBar(os.path.getsize(args.pcap), enabled=not args.no_progress)

    events_iter = iter_pnl_events(
        pcap_path=args.pcap,
        salt=salt,
        anonymize=not args.no_anonymize,
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

    # show top devices by total hits
    top_items: List[Tuple[str, Dict[str, Any]]] = sorted(
        report["devices"].items(),
        key=lambda kv: kv[1].get("total_hits", 0),
        reverse=True
    )[:args.top]

    for dev_id, info in top_items:
        ssids_sorted = sorted(info["ssids"].items(), key=lambda kv: kv[1], reverse=True)
        ssid_list = ", ".join([f"{ssid}({hits})" for ssid, hits in ssids_sorted[:8]])
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

    print_banner(enabled=not args.no_banner, color=not args.no_color)

    salt = args.salt or "frame11-default-salt"
    progress = ProgressBar(os.path.getsize(args.pcap), enabled=not args.no_progress)

    events = list(iter_pnl_events(
        pcap_path=args.pcap,
        salt=salt,
        anonymize=not args.no_anonymize,
        progress=progress,
    ))

    report = build_ssid_totals(events, min_hits=args.min_hits)
    ssids = report["ssids"]

    if not ssids:
        print("[!] No directed-probe SSIDs found (or all filtered).")
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"[+] Report written: {args.out}")
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


def add_common_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--min-hits", type=int, default=2, help="minimum hits threshold per SSID (default: 2)")
    ap.add_argument("--top", type=int, default=10, help="show top N entries (default: 10)")
    ap.add_argument("--salt", default=None, help="salt used for MAC pseudonymization (default: built-in)")
    ap.add_argument("--no-anonymize", action="store_true", help="do not pseudonymize MACs (prints raw addr2)")
    ap.add_argument("--no-banner", action="store_true", help="disable startup banner")
    ap.add_argument("--no-progress", action="store_true", help="disable progress bar")
    ap.add_argument("--no-color", action="store_true", help="disable colored output")


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
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
