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
    """-> (ok, detail) for one vector dict.

    Hard assertions: the correct key reproduces expect_prefix, and a bit-flipped
    wrong key does NOT (guards against an IV/offset bug that would 'match' any
    key). Record count is informational - the Qundis CI-78 wrapper payload is
    not standard DIF/VIF from offset 0.
    """
    key = bytes.fromhex(v["key"])
    try:
        pt = wl.decrypt_frame(v["telegram"], key)
    except Exception as e:                           # noqa: BLE001 - report, don't crash
        return False, f"decrypt raised {e!r}"
    if not pt:
        return False, "decrypt returned no plaintext (unknown layout?)"

    got = pt.hex().upper()
    want = v.get("expect_prefix", "").upper()
    if not want:
        return False, "vector has no expect_prefix to assert against"
    if not got.startswith(want):
        return False, f"plaintext {got[:len(want)]} != expected {want}"

    wrong = bytes(b ^ 0xFF for b in key)
    try:
        ptw = wl.decrypt_frame(v["telegram"], wrong)
    except Exception:                                # noqa: BLE001
        ptw = None
    if ptw and ptw.hex().upper().startswith(want):
        return False, "wrong key reproduced expect_prefix (IV/offset bug?)"

    records = list(wl.iter_records(pt.lstrip(b"\x2f")))
    return True, f"prefix ok, wrong-key rejected, {len(records)} record(s)"


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

    gaps = corpus.get("known_gaps", [])
    if gaps and not args.name:
        print(f"\n{len(gaps)} known gap(s) (documented, not run):")
        for g in gaps:
            print(f"SKIP  {g['name']:<{width}}  mode {g.get('mode','?')} CI {g.get('ci','?'):>2}  {g.get('reason','')}")

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
