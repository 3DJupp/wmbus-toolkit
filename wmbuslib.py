"""
wmbuslib - shared building blocks for the wmbus-toolkit.

Provides: config parsing, wM-Bus telegram parsing, Mode-5 decryption and the
match test. No meter data is hardcoded here; everything comes from meters.conf
or the command line.

The wrapper layout (CI 0x78) was observed on Qundis Q water/heat 5.5: after the
record marker 0D FF 5F comes a length byte, then 5 prefix bytes
(00 82 <2B counter> <access>), followed by the AES-CBC ciphertext as a multiple
of 16. Other vendors may differ; the standard Mode-5 path handles those.
"""

import csv
import os

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

# DIF data lengths per EN 13757-3. 0x0D = variable length (LVAR byte follows).
DIF_LEN = {0x0: 0, 0x1: 1, 0x2: 2, 0x3: 3, 0x4: 4, 0x5: 4,
           0x6: 6, 0x7: 8, 0x9: 1, 0xA: 2, 0xB: 3, 0xC: 4, 0xE: 6}

DEV_TYPE = {"04": "heat", "06": "warm water", "07": "water",
            "08": "heat cost alloc", "0d": "heat/cool", "16": "cold water",
            "37": "radio converter"}

# Bytes that end the record list: idle filler, and 0x00/0xFF padding.
RECORD_END = (0x2F, 0x00, 0xFF)


# ---------------------------------------------------------------- Config

def load_meters(path):
    """Read meters.conf -> list of dicts. Missing file yields an empty list."""
    meters = []
    if not path or not os.path.exists(path):
        return meters
    with open(path) as fh:
        for raw in fh:
            line = raw.split("#")[0].strip()
            if not line:
                continue
            rec = {}
            for part in line.split(","):
                if "=" in part:
                    k, v = part.split("=", 1)
                    rec[k.strip()] = v.strip()
            if rec.get("id"):
                rec.setdefault("name", rec["id"])
                meters.append(rec)
    return meters


def meters_by_id(meters):
    return {m["id"]: m for m in meters}


# ---------------------------------------------------------------- Frame parsing

def clean_hex(s):
    return s.replace("_", "").replace("|", "").strip().upper()


def swap_id(hex8):
    """Turn a 4-byte BCD id from little-endian into display order."""
    return hex8[6:8] + hex8[4:6] + hex8[2:4] + hex8[0:2]


def mfct_code(hex4_le):
    """FLAG manufacturer code from the 15-bit encoding (3x5 bits)."""
    v = int(hex4_le[2:4] + hex4_le[0:2], 16)
    letters = [chr(((v >> s) & 0x1F) + 64) for s in (10, 5, 0)]
    return "".join(letters) if all("A" <= c <= "Z" for c in letters) else hex4_le


def parse_frame(frame):
    """Split a raw telegram into header fields. Returns a dict or None on junk."""
    hx = clean_hex(frame)
    if len(hx) < 22 or any(c not in "0123456789ABCDEF" for c in hx):
        return None
    ci = hx[20:22]
    return {
        "hex": hx,
        "length": int(hx[0:2], 16),
        "mfct": mfct_code(hx[4:8]),
        "id": swap_id(hx[8:16]),
        "version": hx[16:18],
        "dev_type": DEV_TYPE.get(hx[18:20].lower(), hx[18:20]),
        "ci": ci,
        "bytes": len(hx) // 2,
        "encrypted": classify_encryption(hx, ci),
    }


def classify_encryption(hx, ci):
    """Rough class: 'plain', 'aes5', 'wrap' (CI 78) or '?'."""
    if ci == "78":
        return "wrap"
    cfg_at = {"72": 42, "7A": 26}.get(ci)
    if cfg_at and len(hx) >= cfg_at + 4:
        raw = hx[cfg_at:cfg_at + 4]
        mode = (int(raw[2:4] + raw[0:2], 16) >> 8) & 0x0F
        return "plain" if mode == 0 else f"aes{mode}"
    return "?"


# ---------------------------------------------------------------- Crypto (Mode 5)

def find_wrap_blob(b):
    """For the CI-0x78 wrapper: (ciphertext, access_byte) behind 0D FF 5F.

    Layout: 0DFF5F | LVAR | 00 82 <2B ctr> <ACC> | ciphertext (multiple of 16)
    """
    j = b.find(bytes.fromhex("0DFF5F"), 11)
    if j < 0:
        return None, None
    ln = b[j + 3]
    blob = b[j + 4:j + 4 + ln]
    if len(blob) < 6:
        return None, None
    return whole_blocks(blob[5:]), blob[4]


def whole_blocks(data):
    """Cut data down to a multiple of the AES block size."""
    return data[:len(data) - len(data) % 16]


def mode5_parts(b):
    """(address, access, ciphertext) for the standard OMS Mode-5 layouts.

    CI 72: long TPL header  id(4) m(2) ver(1) type(1) acc status cfg(2)
    CI 7A: short TPL header acc status cfg(2)
    The IV address is the TPL address for CI 72, the link-layer one for CI 7A.
    """
    ci = b[10]
    if ci == 0x72 and len(b) > 23:
        return b[15:17] + b[11:15] + b[17:19], b[19], b[23:]
    if ci == 0x7A and len(b) > 15:
        return b[2:10], b[11], b[15:]
    return None, None, None


def build_iv(addr, access):
    """Mode-5 IV: M field(2) + id(4) + version(1) + type(1) + 8x access byte."""
    return addr + bytes([access]) * 8


def decrypt_frame(frame, key):
    """Decrypt a frame with key. Returns plaintext bytes or None."""
    if not HAVE_CRYPTO:
        raise RuntimeError("python3-cryptography is missing")
    b = bytes.fromhex(clean_hex(frame))
    if len(b) < 12:
        return None
    if b[10] == 0x78:                       # Qundis wrapper, link-layer address
        addr = b[2:10]
        cipher, access = find_wrap_blob(b)
    else:                                    # standard Mode 5
        addr, access, cipher = mode5_parts(b)
        cipher = whole_blocks(cipher) if cipher else None
    if not cipher:
        return None
    dec = Cipher(algorithms.AES(key), modes.CBC(build_iv(addr, access))).decryptor()
    return dec.update(cipher) + dec.finalize()


# ---------------------------------------------------------------- Records

def iter_records(p):
    """Walk DIF/VIF records in p, yielding (dif, vifs, data).

    Stops at the first filler byte or at the first record that does not fit
    the remaining bytes, so a wrong key yields few or no records.
    """
    i = 0
    while i < len(p):
        dif = p[i]
        if dif in RECORD_END:
            return
        i += 1
        # skip DIFE chain (storage number, tariff, subunit)
        ext = dif
        while ext & 0x80:
            if i >= len(p):
                return
            ext = p[i]
            i += 1
        # VIF plus optional VIFE chain
        vifs = []
        while True:
            if i >= len(p) or len(vifs) > 10:
                return
            vifs.append(p[i])
            i += 1
            if not vifs[-1] & 0x80:
                break
        n = dif & 0x0F
        if n == 0x0D:
            if i >= len(p):
                return
            ln = p[i]
            i += 1
        else:
            ln = DIF_LEN.get(n)
        if ln is None or i + ln > len(p):
            return
        yield dif, vifs, p[i:i + ln]
        i += ln


def looks_valid(plain):
    """Mode-5 marker 2F2F plus at least one clean record."""
    if not plain or plain[:2] != b"\x2f\x2f":
        return False
    return any(True for _ in iter_records(plain[2:]))


def decode_records(plain):
    """Records as (dif_hex, vif_hex, value_hex) - value in display order."""
    return [(f"{dif:02X}",
             "".join(f"{v:02X}" for v in vifs),
             data[::-1].hex().upper())
            for dif, vifs, data in iter_records(plain[2:])]


# ---------------------------------------------------------------- CSV access

def is_encrypted(row):
    return row.get("ci") == "78" or str(row.get("enc_mode", "")).startswith("aes")


def read_csv_frames(csv_path, only_id=None, only_encrypted=True):
    """Read telegrams from the collect CSV, grouped by meter id."""
    per = {}
    with open(csv_path, newline="") as fh:
        for r in csv.DictReader(fh):
            if only_encrypted and not is_encrypted(r):
                continue
            if only_id and r["id"] != only_id:
                continue
            per.setdefault(r["id"], []).append(r)
    return per
