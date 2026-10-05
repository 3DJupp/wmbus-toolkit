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

HERE = os.path.dirname(os.path.realpath(__file__))  # realpath: works via a symlink
sys.path.insert(0, os.path.dirname(HERE))          # repo root, for wmbuslib
import wmbuslib as wl


def _vtag(v):
    n = len(v.get("expect_values") or [])
    return f", {n} value(s) ok" if n else ""


def _check_values(v, decoded):
    """Assert every expect_values entry appears among the decoded records."""
    want = v.get("expect_values") or []
    for exp in want:
        hit = any(r["quantity"] == exp["quantity"]
                  and r["unit"] == exp.get("unit", "")
                  and r["value"] is not None
                  and abs(float(r["value"]) - float(exp["value"])) <= 1e-6
                  for r in decoded)
        if not hit:
            got = [(r["quantity"], r["value"], r["unit"]) for r in decoded
                   if r["value"] is not None][:6]
            return False, f"expected value {exp} not decoded; got {got}"
    return True, ""


def check(v):
    """-> (ok, detail) for one vector dict.

    Every vector first asserts classify_encryption returns expect_class, so the
    plain / aes5 / wrap discrimination a Qundis meter needs is pinned.

    Plain vectors (key=null) then assert the cleartext record prefix. Encrypted
    vectors assert the correct key reproduces expect_prefix AND that a bit-flipped
    wrong key does NOT (guards against an IV/offset bug that 'matches' any key).
    Record count is informational - the Qundis CI-78 wrapper payload is not
    standard DIF/VIF from offset 0.
    """
    want = v.get("expect_prefix", "").upper()
    if not want:
        return False, "vector has no expect_prefix to assert against"

    parsed = wl.parse_frame(v["telegram"])
    if not parsed:
        return False, "telegram did not parse"
    want_class = v.get("expect_class")
    if want_class and parsed["encrypted"] != want_class:
        return False, f"classified {parsed['encrypted']!r}, expected {want_class!r}"

    # Plain vector: no key, validate the cleartext record prefix directly.
    if v.get("key") in (None, ""):
        app = wl.plain_app_bytes(v["telegram"])
        got = app.hex().upper()
        if not got.startswith(want):
            return False, f"plain payload {got[:len(want)]} != expected {want}"
        ok, why = _check_values(v, wl.decode_values(app))
        if not ok:
            return False, why
        records = list(wl.iter_records(app))
        return True, f"class {parsed['encrypted']}, prefix ok{_vtag(v)}, {len(records)} record(s)"

    # Encrypted vector.
    key = bytes.fromhex(v["key"])
    try:
        pt = wl.decrypt_frame(v["telegram"], key)
    except Exception as e:                           # noqa: BLE001 - report, don't crash
        return False, f"decrypt raised {e!r}"
    if not pt:
        return False, "decrypt returned no plaintext (unknown layout?)"

    got = pt.hex().upper()
    if not got.startswith(want):
        return False, f"plaintext {got[:len(want)]} != expected {want}"

    wrong = bytes(b ^ 0xFF for b in key)
    try:
        ptw = wl.decrypt_frame(v["telegram"], wrong)
    except Exception:                                # noqa: BLE001
        ptw = None
    if ptw and ptw.hex().upper().startswith(want):
        return False, "wrong key reproduced expect_prefix (IV/offset bug?)"

    # The match detector must accept the correct key and reject the wrong one,
    # for every class including the Qundis CI-78 wrapper (no 2F2F prefix).
    if not wl.looks_valid(pt, v["telegram"]):
        return False, "looks_valid rejected the correct key (match detector gap)"
    if ptw is not None and wl.looks_valid(ptw, v["telegram"]):
        return False, "looks_valid accepted a wrong key (false positive)"

    ok, why = _check_values(v, wl.decode_values(pt))
    if not ok:
        return False, why

    records = list(wl.iter_records(pt.lstrip(b"\x2f")))
    return True, (f"class {parsed['encrypted']}, prefix+match ok{_vtag(v)}, "
                  f"wrong-key rejected, {len(records)} rec")


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
