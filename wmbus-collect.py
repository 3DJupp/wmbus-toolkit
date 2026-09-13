#!/usr/bin/env python3
"""
wmbus-collect - collect wmbusmeters raw telegrams deduplicated into a CSV.

Purpose: archive telegrams while AES keys are still missing. Once a key is
available, the history can be decoded retroactively.

  --import LOG [LOG ...]   read existing log files
  --tail LOG               follow a log file live
  --stats                  print CSV statistics only
  --meters meters.conf     mark own meters (mine=1) and name them

Without --meters all telegrams are collected, own and foreign alike.
"""

import argparse
import csv
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wmbuslib as wl

DEFAULT_LOG = "/var/log/wmbusmeters/wmbusmeters.log"

RE_TELEGRAM = re.compile(r"telegram=\|([^|]+)\|\s*([+-]?\d+)?")
RE_LOGTIME = re.compile(r"^\[(\d{4}-\d{2}-\d{2})_(\d{2}:\d{2}:\d{2})\]")

FIELDS = ["first_seen", "id", "name", "mine", "mfct", "version",
          "dev_type", "ci", "enc_mode", "len_bytes", "rssi", "telegram"]

HEADER = ("  Time      Meter ID   Name           Mfct Ver  Crypt  Len    RSSI\n"
          "  " + "-" * 64)


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def to_record(frame, rssi, known):
    info = wl.parse_frame(frame)
    if not info:
        return None
    m = known.get(info["id"], {})
    return {
        "first_seen": "", "id": info["id"], "name": m.get("name", ""),
        "mine": "1" if info["id"] in known else "0",
        "mfct": info["mfct"], "version": info["version"],
        "dev_type": info["dev_type"], "ci": info["ci"],
        "enc_mode": info["encrypted"], "len_bytes": str(info["bytes"]),
        "rssi": rssi or "", "telegram": info["hex"],
    }


class Store:
    """Append-only CSV of telegrams, deduplicated on the raw hex."""

    def __init__(self, path):
        self.path = path
        self.seen = set()
        self.new = self.dup = 0
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fresh = not os.path.exists(path) or os.path.getsize(path) == 0
        if not fresh:
            with open(path, newline="") as fh:
                self.seen = {row["telegram"] for row in csv.DictReader(fh)}
        self.fh = open(path, "a", newline="")
        self.w = csv.DictWriter(self.fh, fieldnames=FIELDS)
        if fresh:
            self.w.writeheader()
            self.fh.flush()

    def add(self, rec, stamp):
        if rec["telegram"] in self.seen:
            self.dup += 1
            return False
        self.seen.add(rec["telegram"])
        rec["first_seen"] = stamp
        self.w.writerow(rec)
        self.fh.flush()
        self.new += 1
        return True

    def close(self):
        self.fh.close()


def fmt(rec, stamp):
    mark = "*" if rec["mine"] == "1" else " "
    return (f"{mark} {stamp[11:]}  {rec['id']:>9}  {rec['name'] or '-':<14} "
            f"{rec['mfct']:<4} v{rec['version']}  {rec['enc_mode']:<5} "
            f"{rec['len_bytes']:>3}B {rec['rssi']:>7}")


def handle_line(line, stamp, store, known):
    """Parse one log line; store and print it if it is a new telegram."""
    m = RE_TELEGRAM.search(line)
    if not m:
        return
    rec = to_record(m.group(1), m.group(2), known)
    if rec and store.add(rec, stamp):
        print(fmt(rec, stamp), flush=True)


def do_import(paths, store, known):
    print(HEADER)
    for path in paths:
        stamp = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
        with open(path, errors="replace") as fh:
            for line in fh:
                t = RE_LOGTIME.match(line)
                if t:
                    stamp = f"{t.group(1)} {t.group(2)}"
                handle_line(line, stamp, store, known)
        print(f"  [{os.path.basename(path)} imported]")


def do_tail(path, store, known):
    print(HEADER)
    proc = subprocess.Popen(["tail", "-n", "0", "-F", path],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        for line in proc.stdout:
            handle_line(line, now(), store, known)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()


def do_stats(path):
    if not os.path.exists(path):
        print(f"No data at {path}")
        return
    with open(path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        print("CSV is empty.")
        return
    per = defaultdict(list)
    for r in rows:
        per[r["id"]].append(r)
    print(f"{len(rows)} telegrams, {len(per)} meters")
    print(f"Range {rows[0]['first_seen']} to {rows[-1]['first_seen']}\n")
    print("  Meter ID   Name           Mfct Ver  Count   Crypt distribution")
    print("  " + "-" * 62)
    for mid in sorted(per, key=lambda k: (-int(per[k][0]["mine"]), k)):
        rs = per[mid]
        f = rs[0]
        dist = " ".join(f"{k}:{v}" for k, v in sorted(Counter(r["enc_mode"] for r in rs).items()))
        mark = "*" if f["mine"] == "1" else " "
        print(f"{mark} {mid:>9}  {f['name'] or '-':<14} {f['mfct']:<4} v{f['version']}  "
              f"{len(rs):>6}  {dist}")
    print("\n* = own meter")


def main():
    ap = argparse.ArgumentParser(description="Collect wmbusmeters telegrams")
    ap.add_argument("--csv", default="telegrams.csv")
    ap.add_argument("--meters", help="meters.conf to mark own meters")
    ap.add_argument("--import", dest="imports", nargs="+", metavar="LOG")
    ap.add_argument("--tail", metavar="LOG", nargs="?", const=DEFAULT_LOG,
                    help=f"follow a log file (default {DEFAULT_LOG})")
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args()

    if args.stats:
        do_stats(args.csv)
        return
    if not args.imports and args.tail is None:
        ap.error("specify --import, --tail or --stats")

    known = wl.meters_by_id(wl.load_meters(args.meters)) if args.meters else {}
    store = Store(args.csv)
    try:
        if args.imports:
            do_import(args.imports, store, known)
        else:
            do_tail(args.tail, store, known)
    finally:
        store.close()
        print(f"\n{store.new} new, {store.dup} duplicates -> {args.csv}")


if __name__ == "__main__":
    main()
