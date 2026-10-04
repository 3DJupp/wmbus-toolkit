#!/usr/bin/env python3
"""
wmbus-keygen - build one combined key-candidate file for wmbus-keycheck.

No illusions: a properly assigned AES-128 key is 16 bytes of randomness, neither
generatable nor brute-forceable. This generator only covers the case where a
default was left in place or the key is derivable from id / serial / install
date. Useful as a quick default-and-derivation test, not an attack on AES.

Output is a single file whose every line carries a scope prefix, so one keycheck
run can test the right keys against every meter without a run.sh wrapper:

  # scope=all       -> tested against every meter
  # scope=<meterid> -> tested only against that meter
  all:repeat_00=00000000000000000000000000000000
  68347172:date_ymd_pad0=32303234...

Workflow (binaries only, no run.sh):

  wmbus-keygen  --meters meters.conf --from-csv telegrams.csv --out candidates.txt
  wmbus-keycheck --csv telegrams.csv --keyfile candidates.txt

Data comes from meters.conf or the command line; the generic categories use only
published AES / wM-Bus test vectors and public string constants. No meter data is
hardcoded.
"""

import argparse
import calendar
import datetime
import hashlib
import hmac
import itertools
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wmbuslib as wl


# ---------------------------------------------------------------- Byte helpers

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
    return digits, bytes.fromhex(packed) if packed else b""


# ---------------------------------------------------------------- Published test keys
#
# Only values that can be cited from a public source are hardcoded here. Each is
# an AES / wM-Bus test or example key, never real meter data.

# NIST AESAVS KAT KeySbox for AES-128 (21 fixed keys, plaintext all-zero).
# Verified against pyca/cryptography vectors (CBCKeySbox128.rsp) - the same
# crypto library this toolkit already depends on.
AESAVS_KEYSBOX_128 = [
    "10a58869d74be5a374cf867cfb473859", "caea65cdbb75e9169ecd22ebe6e54675",
    "a2e2fa9baf7d20822ca9f0542f764a41", "b6364ac4e1de1e285eaf144a2415f7a0",
    "64cf9c7abc50b888af65f49d521944b2", "47d6742eefcc0465dc96355e851b64d9",
    "3eb39790678c56bee34bbcdeccf6cdb5", "64110a924f0743d500ccadae72c13427",
    "18d8126516f8a12ab1a36d9f04d68e51", "f530357968578480b398a3c251cd1093",
    "da84367f325d42d601b4326964802e8e", "e37b1c6aa2846f6fdb413f238b089f23",
    "6c002b682483e0cabcc731c253be5674", "143ae8ed6555aba96110ab58893a8ae1",
    "b69418a85332240dc82492353956ae0c", "71b5c08a1993e1362e4d0ce9b22b78d5",
    "e234cdca2606b81f29408d5f6da21206", "13237c49074a3da078dc1d828bb78c6f",
    "3071a2a48fe6cbd04f1a129098e308f8", "90f42ec0f68385f2ffc5dfc03a654dce",
    "febd9a24d8b65c1c787d50a4ed3619a9",
]

# Other published AES-128 keys.
#   FIPS-197 / NIST SP 800-38A block-cipher-modes example key.
#   (The all-zero GFSbox/VarTxt key and the 000102..0F FIPS-197 sample key are
#    already produced as repeat_00 and ascending below, so they are not repeated.)
PUBLISHED_AES = {
    "sp800_38a_key": "2b7e151628aed2a6abf7158809cf4f3c",
}

# Publicly documented wM-Bus / OMS example keys, source noted in the label.
#   oms_annexN_profA: OMS Spec Vol.2 Annex N, Security Profile A message example.
#   wmbm_readme_demo: the example key used throughout the wmbusmeters README and
#                     its simulation files.
#   oms_testkey_seq:  the ascending example key used in several OMS test frames.
#   All are public test vectors, never real meter data.
PUBLISHED_WMBUS = {
    "oms_annexN_profA": "0102030405060708090a0b0c0d0e0f11",
    "wmbm_readme_demo": "00112233445566778899aabbccddeeff",
    "oms_testkey_seq": "000102030405060708090a0b0c0d0e0f",
    "oms_testkey_seq_rev": "0f0e0d0c0b0a09080706050403020100",
    "wmbm_alt_demo": "0123456789abcdef0123456789abcdef",
}

# 32-bit "hex culture" constants (repeated to 16 bytes).
HEX_QUADS = [
    "deadbeef", "cafebabe", "feedface", "deadc0de", "baadf00d", "8badf00d",
    "cafed00d", "feedbeef", "0defaced", "faceb00c", "badc0ffe", "deadbabe",
    "b16b00b5", "c0ffee00", "1337c0de", "abad1dea",
]

# 8-byte patterns (repeated to 16 bytes), distinct from the quads above.
HEX_OCTETS = [
    "cafebabedeadbeef", "deadbeefcafebabe", "0123456789abcdef",
    "fedcba9876543210", "0f0f0f0f0f0f0f0f", "aaaaaaaa55555555",
]

# Manufacturer / vendor names and their FLAG codes, tried as ASCII keys. Broad
# on purpose: this is a multi-vendor tool, not a Qundis-only one. Each base word
# is expanded to several spellings (title / upper / lower) automatically.
MFCT_BASE = [
    "Qundis", "Allmess", "Kamstrup", "Diehl", "Techem", "Engelmann", "Sensus",
    "Itron", "Landis", "LandisGyr", "Zenner", "Sontex", "Elster", "Apator",
    "Maddalena", "Axioma", "Aquametro", "Integra", "Hydrometer", "Gavazzi",
    "Sappel", "Lorenz", "Relay", "Innotas", "BMeters", "Weptech", "Metrona",
    "ista", "Viterra", "Minol", "Wehrle", "Padmess", "Micronova",
]
# FLAG 3-letter manufacturer codes, tried verbatim and repeated to key length.
MFCT_FLAG_CODES = [
    "QDS", "LUG", "KAM", "TCH", "DME", "HYD", "SEN", "EFE", "SON", "ELS",
    "ITW", "GWF", "NZR", "REL", "AMT", "BMT", "MAD", "AXI", "GAV", "ZEN",
    "APT", "SAP", "LOR", "IST", "EMH", "DZG",
]


def _spellings(words):
    """Expand each base word to title / upper / lower spellings, de-duplicated."""
    out = []
    for w in words:
        for form in (w, w.upper(), w.lower()):
            if form not in out:
                out.append(form)
    return out


MFCT_WORDS = _spellings(MFCT_BASE)

# Sample of the most common passwords (rockyou top list), padded to 16 bytes.
ROCKYOU_TOP = [
    "123456", "12345", "123456789", "password", "iloveyou", "princess",
    "1234567", "rockyou", "12345678", "abc123", "nicole", "daniel", "monkey",
    "babygirl", "jessica", "654321", "michael", "ashley", "qwerty", "111111",
    "iloveu", "000000", "michelle", "tigger", "sunshine", "chocolate",
    "password1", "soccer", "anthony", "friends", "butterfly", "purple",
    "angel", "jordan", "liverpool", "123123", "football", "secret",
]

# Installer / service shorthands.
INSTALLER_WORDS = [
    "INSTALL", "install", "SETUP", "setup", "SERVICE", "MASTER", "master",
    "ADMIN", "admin", "TEST", "test", "DEMO", "0000", "1111", "2222", "1234",
    "12345678", "00000000",
]

# Keyboard walks (QWERTY and the German QWERTZ layout), padded / repeated. People
# who pick a key by "mashing a row" land on one of these surprisingly often.
KEYBOARD_WALKS = [
    "qwerty", "qwertz", "qwertyuiop", "qwertzuiop", "asdfghjkl", "asdfgh",
    "zxcvbnm", "yxcvbnm", "1qaz2wsx", "1q2w3e4r", "qazwsx", "qwer1234",
    "1qazxsw2", "q1w2e3r4", "zaqwsx", "abcd1234",
]


# ---------------------------------------------------------------- Generic (scope=all)

def generic_candidates():
    """-> list of (category, label, key_bytes) tested against every meter."""
    out = []

    # single repeated byte 00..FF (covers the all-zero GFSbox/VarTxt key)
    for v in range(256):
        out.append(("repeat", f"repeat_{v:02X}", bytes([v]) * 16))

    # NIST AESAVS / FIPS test vectors
    out.append(("aes_kat", "ascending_00_0F", bytes(range(16))))
    out.append(("aes_kat", "descending_0F_00", bytes(range(15, -1, -1))))
    out.append(("aes_kat", "test_0123_EF",
                bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")))
    out.append(("aes_kat", "test_FEDC_10",
                bytes.fromhex("FEDCBA9876543210FEDCBA9876543210")))
    for label, hx in PUBLISHED_AES.items():
        out.append(("aes_kat", label, bytes.fromhex(hx)))
    for i, hx in enumerate(AESAVS_KEYSBOX_128):
        out.append(("aes_kat", f"aesavs_keysbox_{i:02d}", bytes.fromhex(hx)))
    # AESAVS VarKey128: key = leftmost n bits set, n = 1..128
    for n in range(1, 129):
        val = ((1 << n) - 1) << (128 - n)
        out.append(("aes_kat", f"aesavs_varkey_{n:03d}", val.to_bytes(16, "big")))

    # published wM-Bus / OMS example keys
    for label, hx in PUBLISHED_WMBUS.items():
        out.append(("wmbus_pub", label, bytes.fromhex(hx)))

    # counting / stepping sequences
    for step in (2, 3, 4):
        out.append(("sequence", f"count_step{step}",
                    bytes((i * step) & 0xFF for i in range(16))))
    # 16- and 32-bit incrementing words, both byte orders (0000 0001 0002 ... and
    # 00000000 00000001 ...). A common "obviously fake" placeholder key.
    out.append(("sequence", "word16_be",
                b"".join(i.to_bytes(2, "big") for i in range(8))))
    out.append(("sequence", "word16_le",
                b"".join(i.to_bytes(2, "little") for i in range(8))))
    out.append(("sequence", "dword32_be",
                b"".join(i.to_bytes(4, "big") for i in range(4))))
    out.append(("sequence", "dword32_le",
                b"".join(i.to_bytes(4, "little") for i in range(4))))
    out.append(("sequence", "nibble_ladder",
                bytes(((i & 0x0F) << 4 | (i & 0x0F)) for i in range(16))))

    # hex-culture constants and byte patterns
    for hx in HEX_QUADS:
        out.append(("hexculture", f"quad_{hx}", rep16(bytes.fromhex(hx))))
    for hx in HEX_OCTETS:
        out.append(("hexculture", f"oct_{hx}", rep16(bytes.fromhex(hx))))
    fib = [0, 1]
    while len(fib) < 16:
        fib.append((fib[-1] + fib[-2]) & 0xFF)
    out.append(("hexculture", "fibonacci_bytes", bytes(fib[:16])))
    primes, n = [], 2
    while len(primes) < 16:
        if all(n % p for p in primes):
            primes.append(n)
        n += 1
    out.append(("hexculture", "prime_bytes", bytes(primes)))

    # ASCII: manufacturer names, FLAG codes, common passwords, installer words
    for w in MFCT_WORDS:
        out.append(("ascii", f"mfct_{w[:12]}_pad0", fit16(w.encode())))
        out.append(("ascii", f"mfct_{w[:12]}_x4", rep16(w.encode())))
    for c in MFCT_FLAG_CODES:
        out.append(("ascii", f"flag_{c}_x4", rep16(c.encode())))
        out.append(("ascii", f"flag_{c}_pad0", fit16(c.encode())))
    for w in ROCKYOU_TOP:
        out.append(("ascii", f"pw_{w[:12]}_pad0", fit16(w.encode())))
        out.append(("ascii", f"pw_{w[:12]}_padsp", fit16(w.encode(), b" ")))
    for w in INSTALLER_WORDS:
        out.append(("ascii", f"inst_{w[:12]}_pad0", fit16(w.encode())))
        out.append(("ascii", f"inst_{w[:12]}_x4", rep16(w.encode())))
    for w in KEYBOARD_WALKS:
        out.append(("ascii", f"kb_{w[:12]}_pad0", fit16(w.encode())))
        out.append(("ascii", f"kb_{w[:12]}_x4", rep16(w.encode())))
    return out


# ---------------------------------------------------------------- Derivation kit

def _hash16(raw):
    """(md5, sha1, sha256) of raw, each truncated to 16 bytes."""
    return (hashlib.md5(raw).digest()[:16],
            hashlib.sha1(raw).digest()[:16],
            hashlib.sha256(raw).digest()[:16])


def derive_keys(sources, pair_sources):
    """Systematically turn raw sources into 16-byte keys.

    sources:      list of (name, raw_bytes, hashable) - each gets pad/repeat
                  variants, and MD5/SHA1/SHA256 truncated to 16 bytes when
                  hashable (hash-of-serial is a realistic lazy key).
    pair_sources: list of (name, raw_bytes) - concatenated pairwise in both
                  orders. Each concatenation is padded/cut to 16 *and* hashed
                  (MD5/SHA1/SHA256, truncated). Hashing a concatenation of two
                  meter facts - e.g. SHA256(mfct||id) or SHA256(id||date) - is
                  the most common lazy KDF, so it is worth the extra lines.

    Returns {label: key_bytes}.
    """
    out = {}
    for name, raw, hashable in sources:
        if not raw:
            continue
        out[f"{name}_pad0"] = fit16(raw)
        out[f"{name}_padF"] = fit16(raw, b"\xff")
        out[f"0_{name}"] = lfit16(raw)
        out[f"{name}_x4"] = rep16(raw)
        if hashable:
            md5, sha1, sha256 = _hash16(raw)
            out[f"{name}_md5"] = md5
            out[f"{name}_sha1"] = sha1
            out[f"{name}_sha256"] = sha256
            # Further lazy-KDF shapes seen in the wild: the tail of sha256, a
            # wider digest truncated, and a double hash.
            out[f"{name}_sha256tail"] = hashlib.sha256(raw).digest()[-16:]
            out[f"{name}_sha512"] = hashlib.sha512(raw).digest()[:16]
            out[f"{name}_sha256x2"] = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:16]
    for (na, ra), (nb, rb) in itertools.permutations(pair_sources, 2):
        if not (ra and rb):
            continue
        cat = ra + rb
        out[f"{na}__{nb}"] = fit16(cat)
        md5, sha1, sha256 = _hash16(cat)
        out[f"{na}__{nb}_md5"] = md5
        out[f"{na}__{nb}_sha1"] = sha1
        out[f"{na}__{nb}_sha256"] = sha256
        # HMAC keyed by the first source: realistic when an installer script
        # derives one key from two printed identifiers instead of storing random.
        out[f"hmac_{na}_{nb}"] = hmac.new(ra, rb, hashlib.sha256).digest()[:16]
    return out


def date_sources(d, tag=""):
    """Raw byte sources for one date/datetime, as (name, bytes, hashable)."""
    if isinstance(d, datetime.datetime):
        dt, has_time = d, True
    else:
        dt, has_time = datetime.datetime(d.year, d.month, d.day), False
    y, m, day, hh, mm = dt.year, dt.month, dt.day, dt.hour, dt.minute
    p = f"date{tag}"
    ymd = f"{y:04d}{m:02d}{day:02d}"
    unix_be = int(calendar.timegm(dt.timetuple())).to_bytes(4, "big")
    src = [
        (f"{p}_ymd", ymd.encode(), True),
        (f"{p}_dmy", f"{day:02d}{m:02d}{y:04d}".encode(), False),
        (f"{p}_iso", f"{y:04d}-{m:02d}-{day:02d}".encode(), False),
        (f"{p}_de", f"{day:02d}.{m:02d}.{y:04d}".encode(), False),
        (f"{p}_bcd", bytes.fromhex(ymd), True),
        (f"{p}_unix_be", unix_be, False),
        (f"{p}_unix_le", unix_be[::-1], False),
    ]
    if has_time:
        hm = f"{hh:02d}{mm:02d}"
        src += [
            (f"{p}_ymdhm", (ymd + hm).encode(), False),
            (f"{p}_hms", f"{hh:02d}{mm:02d}00".encode(), False),
            (f"{p}_bcdt", bytes.fromhex(ymd + hm + "00"), False),
        ]
    return src


def date_bcd(d):
    return bytes.fromhex(f"{d.year:04d}{d.month:02d}{d.day:02d}")


def meter_candidates(m, dates):
    """-> {label: key_bytes} derived for one meter (its own scope)."""
    sources, pair = [], []

    id_hex = m.get("id", "")
    id_be = None
    try:
        if len(id_hex) in (6, 8, 10, 12, 14, 16) and len(id_hex) % 2 == 0:
            id_be = bytes.fromhex(id_hex)
    except ValueError:
        id_be = None
    if id_be:
        id_le = id_be[::-1]
        sources += [("id_be", id_be, True), ("id_le", id_le, True),
                    ("id_ascii", id_hex.encode(), True)]
        pair += [("id_be", id_be), ("id_le", id_le)]
        # id read as a decimal number (the digits printed on the label), packed
        # into 4 bytes both ways - distinct from the BCD bytes above.
        id_digits = "".join(c for c in id_hex if c.isdigit())
        if id_digits:
            idec = (int(id_digits) & 0xFFFFFFFF).to_bytes(4, "big")
            sources += [("id_dec_be", idec, False), ("id_dec_le", idec[::-1], False)]
            rev = id_digits[::-1]
            sources.append(("id_rev_ascii", rev.encode(), True))
            pair.append(("id_rev_ascii", rev.encode()))

    if m.get("serial"):
        digits, bcd = digits_and_bcd(m["serial"])
        if len(digits) >= 2:
            be = (int(digits) & 0xFFFFFFFF).to_bytes(4, "big")
            sources += [("ser_ascii", digits.encode(), True), ("ser_bcd", bcd, True),
                        ("ser_int_be", be, False), ("ser_int_le", be[::-1], False)]
            rev = digits[::-1]
            _, rbcd = digits_and_bcd(rev)
            sources += [("ser_rev_ascii", rev.encode(), True),
                        ("ser_rev_bcd", rbcd, True)]
            pair += [("ser_bcd", bcd), ("ser_ascii", digits.encode())]

    if m.get("model"):
        digits, bcd = digits_and_bcd(m["model"])
        if len(digits) >= 4:
            sources += [("model_ascii", digits.encode(), True), ("model_bcd", bcd, True)]

    # Manufacturer-aware candidates: vendor name / FLAG code, alone and combined
    # with the id. This is what makes the derivation multi-vendor rather than
    # tuned to a single brand. mfct / mfct_name come from meters.conf or are
    # filled in from the meter's own telegrams (see collect_csv_meta).
    vendor_words = []
    for w in (m.get("mfct"), m.get("mfct_name")):
        if not w:
            continue
        for form in (w, w.upper(), w.lower()):
            if form and form not in vendor_words:
                vendor_words.append(form)
    for w in vendor_words[:6]:
        tag = "".join(c for c in w if c.isalnum())[:8] or "v"
        sources.append((f"mfct_{tag}", w.encode(), True))
        if id_be:
            pair.append((f"mfct_{tag}", w.encode()))

    # version byte, if known, as a short combinable source
    ver = m.get("version")
    if ver:
        try:
            vb = bytes.fromhex(ver) if len(ver) == 2 else ver.encode()
            if vb:
                pair.append(("ver", vb))
        except ValueError:
            pass

    # Date sources: the known dates (already expanded by +/- date-window in
    # dates_for_meter), plus the rounded-down primary date (first of the
    # month/year), since install dates are often recorded rounded.
    exp_dates = list(dates[:15])
    if dates:
        d0 = dates[0]
        base = d0.date() if isinstance(d0, datetime.datetime) else d0
        for r in (base.replace(day=1), base.replace(month=1, day=1)):
            if r not in exp_dates:
                exp_dates.append(r)

    for k, d in enumerate(exp_dates):
        tag = "" if k == 0 else str(k + 1)
        dv = date_sources(d, tag)
        sources += dv
        if k == 0:
            for name, raw, _ in dv:
                if name.endswith("_bcd") or name.endswith("_ymd"):
                    pair.append((name, raw))

    cand = derive_keys(sources, pair)

    if id_be and dates:
        dbcd = date_bcd(dates[0])
        x = bytes(a ^ b for a, b in zip(dbcd, id_be))
        xl = bytes(a ^ b for a, b in zip(dbcd, id_be[::-1]))
        if any(x):
            cand["date_xor_id_x4"] = rep16(x)
            cand["date_xor_id_pad0"] = fit16(x)
        if any(xl):
            cand["date_xor_idLE_x4"] = rep16(xl)
    return cand


# ---------------------------------------------------------------- Dates from config / CSV

def parse_install_date(s):
    """Accept YYYY-MM-DD, with optional time, or DD.MM.YYYY. -> date/datetime."""
    if not s:
        return None
    s = s.strip().replace("_", " ").replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
                "%d.%m.%Y %H:%M", "%d.%m.%Y", "%Y%m%d"):
        try:
            dt = datetime.datetime.strptime(s, fmt)
            return dt if ("%H" in fmt) else dt.date()
        except ValueError:
            continue
    return None


def with_window(d, window):
    """Yield d and, when window > 0, +/- window days around it (off-by-one /
    timezone-shifted commissioning dates are a common lazy-key cause)."""
    yield d
    if not window:
        return
    step = datetime.timedelta(days=1)
    for n in range(1, window + 1):
        yield d - n * step
        yield d + n * step


def dates_for_meter(m, global_install, csv_dates, window=0):
    """Ordered, de-duplicated dates for a meter: explicit install date first,
    then dates decoded from that meter's plain telegrams, each optionally
    expanded by +/- `window` days."""
    out, seen = [], set()

    def add(d):
        if d is None:
            return
        for dd in with_window(d, window):
            key = dd.isoformat()
            if key not in seen:
                seen.add(key)
                out.append(dd)

    add(parse_install_date(m.get("installed") or global_install))
    for d in csv_dates.get(m.get("id"), []):
        add(d)
    return out


def collect_csv_meta(csv_path):
    """{meter_id: {mfct, mfct_name, version, dev_type}} from the collect CSV.

    Lets keygen build manufacturer-aware candidates for a meter even when
    meters.conf carries only its id, and lets --all-meters discover every meter
    seen on the air.
    """
    meta = {}
    if not csv_path or not os.path.exists(csv_path):
        return meta
    import csv as _csv
    with open(csv_path, newline="") as fh:
        for r in _csv.DictReader(fh):
            mid = r.get("id")
            if not mid or mid in meta:
                continue
            code = r.get("mfct", "")
            meta[mid] = {
                "mfct": code,
                "mfct_name": wl.mfct_name(code) if code else "",
                "version": r.get("version", ""),
                "dev_type": r.get("dev_type", ""),
                "encrypted": wl.is_encrypted(r),
            }
    return meta


def collect_csv_dates(csv_path):
    """{meter_id: [dates]} decoded from plain telegrams in the collect CSV."""
    per = {}
    if not csv_path or not os.path.exists(csv_path):
        return per
    rows = wl.read_csv_frames(csv_path, only_encrypted=False)
    for mid, telegrams in rows.items():
        seen, dates = set(), []
        for r in telegrams:
            if wl.is_encrypted(r):
                continue
            for d in wl.extract_dates(r.get("telegram", "")):
                key = d.isoformat()
                if key not in seen:
                    seen.add(key)
                    dates.append(d)
        if dates:
            per[mid] = dates
    return per


# ---------------------------------------------------------------- Output

def validate(key):
    """True if key is exactly 16 bytes -> 32 hex chars."""
    return isinstance(key, (bytes, bytearray)) and len(key) == 16


def clean_hex_key(s):
    """A meters.conf/--known-key value -> 16 bytes, or raise ValueError."""
    hx = s.strip().replace(" ", "").replace(":", "").replace("-", "")
    if len(hx) != 32:
        raise ValueError(f"key needs 32 hex chars, has {len(hx)}: {s!r}")
    return bytes.fromhex(hx)


def build_entries(generic, meters, global_install, csv_dates, date_window=0):
    """-> (entries, counts). entries = list of (scope, category, label, hex).

    Dedup rule: no key is tested twice against the same meter. All-scope hexes
    are unique among themselves; a meter drops any hex already in the all-scope
    set (it is covered there) and any repeat within its own scope. Identical
    hexes across two different meters are kept - they are separate test sets.
    """
    entries, counts = [], {}
    seen_all = set()

    def bump(cat, scope):
        counts.setdefault(scope, {})
        counts[scope][cat] = counts[scope].get(cat, 0) + 1

    for cat, label, key in generic:
        if not validate(key):
            continue
        hx = key.hex().upper()
        if hx in seen_all:
            continue
        seen_all.add(hx)
        entries.append(("all", cat, label, hx))
        bump(cat, "all")

    for m in meters:
        mid = m["id"]
        seen_m = set()

        # A key already known (meters.conf `key=`, or --key on a single meter)
        # goes in first, under its own category, so it is tried before any
        # guess and is never confused with a derived candidate.
        known = m.get("key")
        if known:
            try:
                kb = clean_hex_key(known)
            except ValueError as e:
                print(f"  meters.conf: {mid}: {e}", file=sys.stderr)
                kb = None
            if kb and validate(kb):
                hx = kb.hex().upper()
                seen_m.add(hx)
                entries.append((mid, "known", "known_key", hx))
                bump("known", mid)

        cand = meter_candidates(m, dates_for_meter(m, global_install, csv_dates, date_window))
        for label, key in cand.items():
            if not validate(key):
                continue
            hx = key.hex().upper()
            if hx in seen_all or hx in seen_m:
                continue
            seen_m.add(hx)
            entries.append((mid, category_of(label), label, hx))
            bump(category_of(label), mid)
    return entries, counts


def category_of(label):
    """Coarse category from a derived-key label, for the count report."""
    if "xor" in label:
        return "xor"
    if label.endswith(("_md5", "_sha1", "_sha256")):
        return "hash"
    if "__" in label:
        return "combo"
    if label.startswith("date"):
        return "date"
    if label.startswith("ser"):
        return "serial"
    if label.startswith("model"):
        return "model"
    if label.startswith(("id_", "0_id")):
        return "id"
    if label.startswith("mfct"):
        return "mfct"
    return "other"


def write_combined(path, entries, counts):
    with open(path, "w") as fh:
        fh.write("# wmbus-keygen candidate file\n")
        fh.write("# format: <scope>:<label>=<32 hex>\n")
        fh.write("#   scope=all       -> tested against every meter\n")
        fh.write("#   scope=<meterid> -> tested only against that meter\n")
        fh.write(f"# {len(entries)} candidates total\n")
        for scope, _cat, label, hx in entries:
            fh.write(f"{scope}:{label}={hx}\n")
    return len(entries)


RUN_SH = """#!/bin/bash
# Legacy runner: tests all candidates against the matching meters.
# The scoped combined file plus a single `wmbus-keycheck --keyfile` run makes
# this unnecessary; kept only for the old per-file layout.
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


def write_legacy(outdir, entries, meters):
    """Optional old layout: candidates_generic.txt + per-meter files + run.sh."""
    os.makedirs(outdir, exist_ok=True)
    by_scope = {}
    for scope, _cat, label, hx in entries:
        by_scope.setdefault(scope, []).append(f"{label}={hx}")

    gen = by_scope.get("all", [])
    with open(os.path.join(outdir, "candidates_generic.txt"), "w") as fh:
        fh.write(f"# Generic defaults, apply to any meter\n# {len(gen)} candidates\n")
        fh.write("\n".join(sorted(gen)) + "\n")

    for m in meters:
        mid = m["id"]
        lines = by_scope.get(mid, [])
        name = m.get("name") or mid
        safe = "".join(c if c.isalnum() else "_" for c in name)
        with open(os.path.join(outdir, f"candidates_{mid}_{safe}.txt"), "w") as fh:
            fh.write(f"# Derived for {name} (id {mid})\n# {len(lines)} candidates\n")
            fh.write("\n".join(sorted(lines)) + "\n")

    run_path = os.path.join(outdir, "run.sh")
    with open(run_path, "w") as fh:
        fh.write(RUN_SH)
    os.chmod(run_path, 0o755)
    return run_path


# ---------------------------------------------------------------- Report

def print_report(entries, counts):
    order = ["all"] + [s for s in counts if s != "all"]
    for scope in order:
        cats = counts.get(scope, {})
        total = sum(cats.values())
        head = "scope=all (every meter)" if scope == "all" else f"scope={scope}"
        print(f"\n{head}: {total} candidates")
        for cat in sorted(cats):
            print(f"    {cat:<12}{cats[cat]:>5}")
    print(f"\nTotal lines written: {len(entries)}")


# ---------------------------------------------------------------- Main

def main():
    ap = argparse.ArgumentParser(description="Generate one combined key-candidate file")
    ap.add_argument("--out", default="candidates.txt",
                    help="combined output file (default candidates.txt)")
    ap.add_argument("--meters", help="read meters.conf")
    ap.add_argument("--from-csv", dest="from_csv",
                    help="collect CSV: decode install/billing dates from plain telegrams")
    ap.add_argument("--install-date",
                    help="global fallback install date (YYYY-MM-DD[ HH:MM] or DD.MM.YYYY)")
    ap.add_argument("--date-window", type=int, default=0, metavar="N",
                    help="also derive keys for +/- N days around each known date "
                         "(covers off-by-one / timezone-shifted commissioning dates)")
    ap.add_argument("--id", help="single meter: meter id")
    ap.add_argument("--serial", help="single meter: serial number")
    ap.add_argument("--model", help="single meter: model number")
    ap.add_argument("--name", help="single meter: name")
    ap.add_argument("--installed", help="single meter: install date")
    ap.add_argument("--known-key", metavar="HEX",
                    help="single meter: a key already known (32 hex chars), "
                         "written first and tried before any guess")
    ap.add_argument("--all-meters", action="store_true",
                    help="with --from-csv: build candidates for every meter seen "
                         "in the CSV, not only those in meters.conf")
    ap.add_argument("--legacy-runner", metavar="DIR",
                    help="also write the old per-file layout plus run.sh into DIR")
    args = ap.parse_args()

    meters = wl.load_meters(args.meters) if args.meters else []
    if args.id:
        meters.append({"id": args.id, "serial": args.serial, "model": args.model,
                       "name": args.name or args.id, "installed": args.installed,
                       "key": args.known_key})

    csv_meta = collect_csv_meta(args.from_csv) if args.from_csv else {}
    csv_dates = collect_csv_dates(args.from_csv) if args.from_csv else {}

    # --all-meters: build per-meter candidates for every meter seen in the CSV,
    # not only the ones listed in meters.conf. Encrypted meters first.
    if args.all_meters:
        known_ids = {m["id"] for m in meters}
        for mid, info in csv_meta.items():
            if mid not in known_ids:
                meters.append({"id": mid, "name": info.get("mfct_name") or mid})

    # Enrich every meter with manufacturer / version decoded from its telegrams,
    # unless meters.conf already set those fields explicitly.
    for m in meters:
        info = csv_meta.get(m["id"])
        if not info:
            continue
        for field in ("mfct", "mfct_name", "version", "dev_type"):
            if not m.get(field) and info.get(field):
                m[field] = info[field]

    generic = generic_candidates()
    entries, counts = build_entries(generic, meters, args.install_date, csv_dates,
                                    args.date_window)

    outdir = os.path.dirname(args.out)
    if outdir:
        os.makedirs(outdir, exist_ok=True)
    write_combined(args.out, entries, counts)
    print_report(entries, counts)
    print(f"\nWritten: {args.out}")
    print(f"Test:    wmbus-keycheck --csv telegrams.csv --keyfile {args.out}")

    if not meters:
        print("\nNo meters given - only generic (scope=all) defaults built.")
        print("Add your own with --meters meters.conf or --id/--serial/--installed.")

    if args.legacy_runner:
        run_path = write_legacy(args.legacy_runner, entries, meters)
        print(f"\nLegacy layout + runner written: bash {run_path} telegrams.csv")


if __name__ == "__main__":
    main()
