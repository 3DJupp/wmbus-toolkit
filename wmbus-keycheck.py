#!/usr/bin/env python3
"""
wmbus-keycheck - test AES key candidates against collected telegrams.

The match test is two-stage: the decrypted frame must start with 2F2F (OMS
Mode-5 filler bytes) and then yield valid DIF/VIF records. A real key decrypts
practically every telegram; isolated random hits are filtered out.

Candidate files from wmbus-keygen carry a scope prefix, so a single run tests
the right keys against every meter (no run.sh needed):

  all:repeat_00=...        tested against every meter
  68347172:date_ymd=...    tested only against meter 68347172

Legacy lines without a scope (label=hex) are treated as scope=all.

  wmbus-keycheck --csv telegrams.csv --keyfile candidates.txt
  wmbus-keycheck --id 12345678 --key <32hex>
  wmbus-keycheck --csv telegrams.csv --key <key> --decode-all --out plaintext.csv
  wmbus-keycheck --selftest --keyfile candidates.txt
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
    """Try key on up to `sample` rows -> (hits, tries, first valid plaintext).

    Aborts early once a match is arithmetically impossible: the dominant case
    is a wrong key that fails the first few telegrams, so this keeps a run over
    thousands of candidates in the seconds range. A real key never trips the
    early exit (it has no misses), so MATCH detection stays exact.
    """
    budget = min(sample, len(rows))
    hits = tries = 0
    example = None
    for idx in range(budget):
        remaining = budget - idx - 1
        try:
            plain = wl.decrypt_frame(rows[idx]["telegram"], key)
        except Exception:
            continue
        tries += 1
        if wl.looks_valid(plain):
            hits += 1
            example = example or plain
        # give up when neither the min-hits nor the ratio can still be reached
        if hits + remaining < MATCH_MIN_HITS:
            break
        if hits + remaining < MATCH_RATIO * (tries + remaining):
            break
    return hits, tries, example


def show(plain):
    print("     decrypted:", plain[:16].hex().upper(), "...")
    for dif, vif, val in wl.decode_records(plain)[:6]:
        print(f"       DIF {dif} VIF {vif}  = {val}")


def parse_key_line(ln):
    """One keyfile line -> (scope, label, key_bytes) or None.

    Accepts 'scope:label=hex' and legacy 'label=hex' (scope defaults to all).
    """
    ln = ln.split("#")[0].strip()
    if not ln:
        return None
    scope = "all"
    head, _, _tail = ln.partition("=")
    if ":" in head:                       # scope prefix present
        scope, ln = ln.split(":", 1)
    label, _, cand = ln.rpartition("=")
    return scope.strip(), (label or cand).strip()[:26], clean_key(cand)


def gather_keys(args):
    """-> list of (scope, label, key_bytes) from --key and/or --keyfile."""
    keys = []
    if args.key:
        try:
            keys.append(("all", "--key", clean_key(args.key)))
        except ValueError as e:
            sys.exit(str(e))
    if args.keyfile:
        with open(args.keyfile) as fh:
            for ln in fh:
                try:
                    parsed = parse_key_line(ln)
                except ValueError as e:
                    print(f"  skipped: {e}", file=sys.stderr)
                    continue
                if parsed:
                    keys.append(parsed)
    if not keys:
        sys.exit("No key given. Use --key or --keyfile.")
    return keys


def keys_for(keys, mid):
    """Candidates applicable to one meter: its own scope plus the all-keys."""
    return [(label, kb) for scope, label, kb in keys if scope in ("all", mid)]


def pick_key(rows, keys, mid, sample):
    for label, kb in keys_for(keys, mid):
        hits, tries, _ = test_key(rows, kb, sample)
        if is_match(hits, tries):
            return label, kb
    return None


def run_check(per, keys, sample):
    any_hit = False
    for mid in sorted(per):
        rows = per[mid]
        applicable = keys_for(keys, mid)
        print(f"\n=== {mid}  ({len(rows)} telegrams, {len(applicable)} candidates) ===")
        found = False
        for label, key in applicable:
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
            hit = pick_key(rows, keys, mid, sample)
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


# ---------------------------------------------------------------- Self-test

def synth_frame(key, access):
    """A synthetic OMS Mode-5 (CI 7A) telegram encrypted with `key`."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    plain = b"\x2f\x2f" + bytes.fromhex("0C13913412000B3B10020042") 
    while len(plain) % 16:
        plain += b"\x2f"
    mfield = bytes.fromhex("2D2C")
    idle = bytes.fromhex("72713468")           # id 68347172 (little-endian)
    ver, typ = b"\x01", b"\x07"
    addr = mfield + idle + ver + typ
    enc = Cipher(algorithms.AES(key), modes.CBC(wl.build_iv(addr, access))).encryptor()
    ct = enc.update(plain) + enc.finalize()
    after = (b"\x44" + mfield + idle + ver + typ +
             bytes([0x7A, access, 0x00]) + bytes.fromhex("0005") + ct)
    return (bytes([len(after)]) + after).hex().upper()


def run_selftest(keys):
    """Encrypt frames with a candidate key; that key must MATCH, a wrong one not."""
    if not wl.HAVE_CRYPTO:
        sys.exit("python3-cryptography is missing")
    all_keys = [(label, kb) for scope, label, kb in keys if scope == "all"]
    if not all_keys:
        sys.exit("self-test needs at least one scope=all candidate in the keyfile")
    good_label, good = all_keys[0]
    rows = [{"telegram": synth_frame(good, acc)} for acc in (0x2A, 0x2B, 0x2C, 0x2D, 0x2E)]

    ok = True
    hits, tries, _ = test_key(rows, good, len(rows))
    if is_match(hits, tries):
        print(f"PASS  real key '{good_label}' matches ({hits}/{tries})")
    else:
        ok = False
        print(f"FAIL  real key '{good_label}' did not match ({hits}/{tries})")

    wrong = bytes((b ^ 0xFF) for b in good)     # a key guaranteed not to be it
    hits, tries, _ = test_key(rows, wrong, len(rows))
    if is_match(hits, tries):
        ok = False
        print(f"FAIL  wrong key falsely matched ({hits}/{tries})")
    else:
        print(f"PASS  wrong key rejected ({hits}/{tries})")

    # no other candidate in the file may match a frame that isn't theirs
    false_hits = [label for label, kb in all_keys
                  if kb != good and is_match(*test_key(rows, kb, len(rows))[:2])]
    if false_hits:
        ok = False
        print(f"FAIL  {len(false_hits)} other candidate(s) falsely matched: "
              f"{', '.join(false_hits[:5])}")
    else:
        print(f"PASS  no false positive among {len(all_keys)} scope=all candidates")

    print("\nself-test:", "OK" if ok else "FAILED")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description="Test AES keys against telegrams")
    ap.add_argument("--csv", default="telegrams.csv")
    ap.add_argument("--id", help="only this meter id")
    ap.add_argument("--key", help="a single key, 32 hex chars")
    ap.add_argument("--keyfile", help="combined candidate file, one per line")
    ap.add_argument("--sample", type=int, default=40, help="telegrams per test")
    ap.add_argument("--decode-all", action="store_true")
    ap.add_argument("--out", default="decoded.csv")
    ap.add_argument("--selftest", action="store_true",
                    help="verify match logic on synthetic frames, then exit")
    args = ap.parse_args()

    if not wl.HAVE_CRYPTO:
        sys.exit("python3-cryptography is missing:  apt install python3-cryptography")

    if args.selftest:
        run_selftest(gather_keys(args))
        return

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
