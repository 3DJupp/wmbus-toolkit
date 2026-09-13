#!/usr/bin/env python3
"""
wmbus-keycheck - test AES keys against collected telegrams.

The match test is two-stage: the decrypted frame must start with 2F2F (OMS
Mode-5 filler bytes) and then yield valid DIF/VIF records. A real key decrypts
practically every telegram; isolated random hits are filtered out.

  wmbus-keycheck --id 12345678 --key <32hex>
  wmbus-keycheck --keyfile candidates.txt
  wmbus-keycheck --keyfile keys/candidates_generic.txt --id 12345678
  wmbus-keycheck --id 12345678 --key <key> --decode-all --out plaintext.csv
"""

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wmbuslib as wl

# A key counts as a match when it cleanly decrypts nearly all sampled
# telegrams and not just a lucky few.
MATCH_RATIO = 0.9
MATCH_MIN_HITS = 3
PARTIAL_RATIO = 0.3


def clean_key(s):
    hx = s.strip().replace(" ", "").replace(":", "").replace("-", "")
    if len(hx) != 32:
        raise ValueError(f"key needs 32 hex chars, has {len(hx)}: {s!r}")
    return bytes.fromhex(hx)


def is_match(hits, tries):
    return tries > 0 and hits >= MATCH_MIN_HITS and hits / tries >= MATCH_RATIO


def test_key(rows, key, sample):
    """Try key on up to `sample` rows -> (hits, tries, first valid plaintext)."""
    hits = tries = 0
    example = None
    for r in rows[:sample]:
        try:
            plain = wl.decrypt_frame(r["telegram"], key)
        except Exception:
            continue
        tries += 1
        if wl.looks_valid(plain):
            hits += 1
            example = example or plain
    return hits, tries, example


def show(plain):
    print("     decrypted:", plain[:16].hex().upper(), "...")
    for dif, vif, val in wl.decode_records(plain)[:6]:
        print(f"       DIF {dif} VIF {vif}  = {val}")


def gather_keys(args):
    """-> list of (label, key_bytes) from --key and/or --keyfile."""
    keys = []
    if args.key:
        try:
            keys.append(("--key", clean_key(args.key)))
        except ValueError as e:
            sys.exit(str(e))
    if args.keyfile:
        with open(args.keyfile) as fh:
            for ln in fh:
                ln = ln.split("#")[0].strip()
                if not ln:
                    continue
                label, _, cand = ln.rpartition("=")
                try:
                    keys.append(((label or cand)[:26], clean_key(cand)))
                except ValueError as e:
                    print(f"  skipped: {e}", file=sys.stderr)
    if not keys:
        sys.exit("No key given. Use --key or --keyfile.")
    return keys


def pick_key(rows, keys, sample):
    for label, kb in keys:
        hits, tries, _ = test_key(rows, kb, sample)
        if is_match(hits, tries):
            return label, kb
    return None


def run_check(per, keys, sample):
    any_hit = False
    for mid in sorted(per):
        rows = per[mid]
        print(f"\n=== {mid}  ({len(rows)} telegrams) ===")
        found = False
        for label, key in keys:
            hits, tries, ex = test_key(rows, key, sample)
            if is_match(hits, tries):
                print(f"  MATCH   {label}   {hits}/{tries} clean")
                found = any_hit = True
                if ex:
                    show(ex)
                break
            if tries and hits / tries >= PARTIAL_RATIO:
                print(f"  partial {label}   {hits}/{tries} - likely coincidence")
        if not found:
            print("  no candidate matches")
    if not any_hit:
        print("\nNo key matched. Expected while the real keys are missing - "
              "guessing won't help, the key comes from the metering provider.")
    return any_hit


def run_decode_all(per, keys, out_path, sample):
    fields = ["first_seen", "id", "dif", "vif", "value_hex", "telegram"]
    written = 0
    with open(out_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for mid, rows in per.items():
            hit = pick_key(rows, keys, sample)
            if not hit:
                print(f"  {mid}: no matching key")
                continue
            label, kb = hit
            print(f"  {mid}: decoding with {label} ({len(rows)} telegrams)")
            for r in rows:
                try:
                    plain = wl.decrypt_frame(r["telegram"], kb)
                except Exception:
                    continue
                if not wl.looks_valid(plain):
                    continue
                for dif, vif, val in wl.decode_records(plain):
                    w.writerow({"first_seen": r["first_seen"], "id": mid,
                                "dif": dif, "vif": vif, "value_hex": val,
                                "telegram": r["telegram"]})
                    written += 1
    print(f"\n{written} records -> {out_path}")


def main():
    ap = argparse.ArgumentParser(description="Test AES keys against telegrams")
    ap.add_argument("--csv", default="telegrams.csv")
    ap.add_argument("--id", help="only this meter id")
    ap.add_argument("--key", help="a single key, 32 hex chars")
    ap.add_argument("--keyfile", help="file with candidates, one per line")
    ap.add_argument("--sample", type=int, default=60, help="telegrams per test")
    ap.add_argument("--decode-all", action="store_true")
    ap.add_argument("--out", default="decoded.csv")
    args = ap.parse_args()

    if not wl.HAVE_CRYPTO:
        sys.exit("python3-cryptography is missing:  apt install python3-cryptography")
    if not os.path.exists(args.csv):
        sys.exit(f"CSV not found: {args.csv}")

    keys = gather_keys(args)
    per = wl.read_csv_frames(args.csv, args.id)
    if not per:
        sys.exit("No matching (encrypted) telegrams in the CSV.")

    if args.decode_all:
        run_decode_all(per, keys, args.out, args.sample)
    else:
        run_check(per, keys, args.sample)


if __name__ == "__main__":
    main()
