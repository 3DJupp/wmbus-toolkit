#!/usr/bin/env python3
"""
run_vectors - validate wmbuslib.decrypt_frame against a corpus of public,
citable wM-Bus / OMS test vectors (tests/vectors.json).

Unlike the encrypt-then-decrypt self-test in wmbus-keycheck (which proves the
crypto round-trips against itself), this runs the decoder against externally
sourced vectors - the OMS Annex N Profile A example and the MIT-licensed
wmbusmeters test telegrams - so a regression in the parser or IV construction
is caught against independent references, not just our own output.

    python3 tests/run_vectors.py                # all vectors in tests/vectors.json
    python3 tests/run_vectors.py --file foo.json
    python3 tests/run_vectors.py --name wmbm_waterstarm

Exit code 0 only if every vector decrypts to its expected plaintext prefix and
yields at least one decodable record; non-zero otherwise, so it drops into CI.
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))          # repo root, for wmbuslib
import wmbuslib as wl


def check(v):
    """-> (ok, detail) for one vector dict."""
    key = bytes.fromhex(v["key"])
    try:
        pt = wl.decrypt_frame(v["telegram"], key)
    except Exception as e:                           # noqa: BLE001 - report, don't crash
        return False, f"decrypt raised {e!r}"
    if not pt:
        return False, "decrypt returned no plaintext (unknown layout?)"

    got = pt.hex().upper()
    want = v.get("expect_prefix", "").upper()
    if want and not got.startswith(want):
        return False, f"plaintext {got[:len(want)]} != expected {want}"

    # 0x2F is OMS idle filler and can lead/pad the block; strip it before the
    # record walk, which otherwise treats the first 0x2F as end-of-list.
    body = pt.lstrip(b"\x2f")
    records = list(wl.iter_records(body))
    if not records:
        return False, f"decrypted ok but no records parsed (pt={got[:16]}...)"

    return True, f"{len(records)} record(s), pt[:{max(len(want),8)}]={got[:max(len(want),8)]}"


def main():
    ap = argparse.ArgumentParser(description="Validate the decoder against public test vectors")
    ap.add_argument("--file", default=os.path.join(HERE, "vectors.json"),
                    help="vector corpus (default tests/vectors.json)")
    ap.add_argument("--name", help="run only the vector with this name")
    args = ap.parse_args()

    if not wl.HAVE_CRYPTO:
        sys.exit("python3-cryptography is missing")

    with open(args.file) as fh:
        corpus = json.load(fh)
    vectors = corpus["vectors"]
    if args.name:
        vectors = [v for v in vectors if v["name"] == args.name]
        if not vectors:
            sys.exit(f"no vector named {args.name!r} in {args.file}")

    width = max(len(v["name"]) for v in vectors)
    passed = 0
    for v in vectors:
        ok, detail = check(v)
        passed += ok
        tag = "PASS" if ok else "FAIL"
        print(f"{tag}  {v['name']:<{width}}  mode {v.get('mode','?')} CI {v.get('ci','?'):>2}  {detail}")

    total = len(vectors)
    print(f"\n{passed}/{total} vectors passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
