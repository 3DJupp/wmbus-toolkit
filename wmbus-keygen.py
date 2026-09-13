#!/usr/bin/env python3
"""
wmbus-keygen - build key candidate lists for wmbus-keycheck.

No illusions: a properly assigned AES-128 key is 16 bytes of randomness, neither
generatable nor brute-forceable. This generator only covers the case where a
default was left in place or the key is derivable from id/serial. Useful as a
quick check, not an attack on the crypto.

Data comes from meters.conf or the command line:

  wmbus-keygen --meters meters.conf --out keys/
  wmbus-keygen --id 12345678 --serial 1234567890 --name MeterA --out keys/
  wmbus-keygen --out keys/          # generic defaults only

Produces candidates_generic.txt plus candidates_<id>_<name>.txt per meter and a
run.sh that tests everything against the matching meters.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wmbuslib as wl


# ---------------------------------------------------------------- Helpers

def fit16(b, fill=b"\x00"):
    """Right-pad (or cut) to 16 bytes."""
    return (b + fill * 16)[:16]


def lfit16(b):
    """Left-pad with zeros (or cut) to 16 bytes."""
    return (b"\x00" * 16 + b)[-16:]


def rep16(b):
    """Repeat b until 16 bytes are filled."""
    return (b * (16 // len(b) + 1))[:16] if b else b"\x00" * 16


def digits_and_bcd(s):
    """Digits of s as a string and as packed BCD bytes."""
    digits = "".join(c for c in s if c.isdigit())
    packed = digits if len(digits) % 2 == 0 else "0" + digits
    return digits, bytes.fromhex(packed)


# ---------------------------------------------------------------- Categories

def generic_candidates():
    out = {f"repeat_{v:02X}": bytes([v]) * 16 for v in range(256)}
    out["ascending_00_0F"] = bytes(range(16))
    out["descending_0F_00"] = bytes(range(15, -1, -1))
    out["test_0123_EF"] = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    out["test_FEDC_10"] = bytes.fromhex("FEDCBA9876543210FEDCBA9876543210")
    out["nibble_count"] = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    for w in ("QUNDIS", "qundis", "ALLMESS", "allmess", "PASSWORD", "password",
              "0000000000000000", "1234567890123456", "KEY", "TESTKEY", "DEFAULT"):
        out[f"ascii_{w[:12]}"] = fit16(w.encode())
        out[f"asciirep_{w[:12]}"] = rep16(w.encode())
    return out


def id_candidates(hexid):
    try:
        b = bytes.fromhex(hexid)
    except ValueError:
        return {}
    le = b[::-1]
    a = hexid.encode()
    return {
        "id_x4": rep16(b), "idLE_x4": rep16(le),
        "id_then_0": fit16(b), "0_then_id": lfit16(b),
        "id_then_F": fit16(b, b"\xff"), "idLE_then_0": fit16(le),
        "ascii_id_pad0": fit16(a), "ascii_id_padsp": fit16(a, b" "),
        "ascii_id_rep": rep16(a),
    }


def serial_candidates(dec, tag="ser"):
    digits, bcd = digits_and_bcd(dec)
    if len(digits) < 2:
        return {}
    a = digits.encode()
    be = (int(digits) & 0xFFFFFFFF).to_bytes(4, "big")
    return {
        f"{tag}_ascii_pad0": fit16(a), f"{tag}_ascii_padsp": fit16(a, b" "),
        f"{tag}_ascii_rep": rep16(a),
        f"{tag}_bcd_pad0": fit16(bcd), f"{tag}_0_bcd": lfit16(bcd),
        f"{tag}_bcd_rep": rep16(bcd),
        f"{tag}_int_be_x4": rep16(be), f"{tag}_int_le_x4": rep16(be[::-1]),
        f"{tag}_int_be_pad0": fit16(be),
    }


def combo_candidates(hexid, dec):
    try:
        b = bytes.fromhex(hexid)
    except ValueError:
        return {}
    digits, bcd = digits_and_bcd(dec)
    if not digits:
        return {}
    a = digits.encode()
    return {
        "id_serbcd": fit16(b + bcd), "serbcd_id": fit16(bcd + b),
        "id_ser_asc": fit16(b + a), "ser_asc_id": fit16(a + b),
    }


# ---------------------------------------------------------------- Writing

def write_file(path, cand, header):
    seen, lines = set(), []
    for label, key in cand.items():
        hx = key.hex().upper()
        if len(key) != 16 or hx in seen:
            continue
        seen.add(hx)
        lines.append(f"{label}={hx}")
    with open(path, "w") as fh:
        fh.write(f"# {header}\n# {len(lines)} unique candidates\n")
        fh.write("\n".join(sorted(lines)) + "\n")
    return len(lines)


def build_meter_file(outdir, m):
    cand = dict(id_candidates(m["id"]))
    if m.get("serial"):
        cand.update(serial_candidates(m["serial"]))
        cand.update(combo_candidates(m["id"], m["serial"]))
    if m.get("model"):
        digits, _ = digits_and_bcd(m["model"])
        if len(digits) >= 4:
            cand.update(serial_candidates(digits, tag="model"))
    name = m.get("name") or m["id"]
    safe = "".join(c if c.isalnum() else "_" for c in name)
    fname = f"candidates_{m['id']}_{safe}.txt"
    n = write_file(os.path.join(outdir, fname), cand, f"Derived for {name} (id {m['id']})")
    return fname, n


RUN_SH = """#!/bin/bash
# Tests all candidates against the matching meters.
# Usage: bash run.sh [path/to/telegrams.csv]
CSV="${1:-/var/lib/wmbusmeters/telegrams.csv}"
DIR="$(cd "$(dirname "$0")" && pwd)"
KEYCHECK="${KEYCHECK:-wmbus-keycheck}"
for f in "$DIR"/candidates_*.txt; do
  case "$f" in */candidates_generic.txt) continue;; esac
  id=$(basename "$f" | cut -d_ -f2)
  echo "##### Meter $id #####"
  "$KEYCHECK" --csv "$CSV" --id "$id" --keyfile "$DIR/candidates_generic.txt"
  "$KEYCHECK" --csv "$CSV" --id "$id" --keyfile "$f"
done
"""


def main():
    ap = argparse.ArgumentParser(description="Generate key candidates")
    ap.add_argument("--out", default="keys", help="output directory (default keys/)")
    ap.add_argument("--meters", help="read meters.conf")
    ap.add_argument("--id", help="single meter: meter id")
    ap.add_argument("--serial", help="single meter: serial number")
    ap.add_argument("--model", help="single meter: model number")
    ap.add_argument("--name", help="single meter: name")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    meters = wl.load_meters(args.meters) if args.meters else []
    if args.id:
        meters.append({"id": args.id, "serial": args.serial,
                       "model": args.model, "name": args.name or args.id})

    n = write_file(os.path.join(args.out, "candidates_generic.txt"),
                   generic_candidates(), "Generic defaults, apply to any meter")
    print(f"{'candidates_generic.txt':<40}{n:>5} candidates")

    if not meters:
        print("\nNo meters given - only generic defaults built.")
        print("Add your own with --meters meters.conf or --id/--serial.")
    for m in meters:
        fname, cnt = build_meter_file(args.out, m)
        print(f"{fname:<40}{cnt:>5} candidates")

    run_path = os.path.join(args.out, "run.sh")
    with open(run_path, "w") as fh:
        fh.write(RUN_SH)
    os.chmod(run_path, 0o755)
    print(f"\nrun.sh written. Test:  bash {run_path} path/to/telegrams.csv")


if __name__ == "__main__":
    main()
