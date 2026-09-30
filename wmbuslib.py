"""
wmbuslib - shared building blocks for the wmbus-toolkit.

A vendor-neutral wM-Bus / OMS library: config parsing, telegram header parsing,
device-type and manufacturer decoding, encryption classification across the
common CI layouts, and Mode-5 (AES-CBC) decryption. No meter data is hardcoded
here; everything comes from meters.conf or the command line.

Decryption is deliberately broad. For a given key several plausible layouts and
IV addresses are tried (short and long TPL headers, and the CI-0x78 vendor
wrapper first seen on Qundis Q water/heat 5.5). The two-stage validator
(looks_valid) decides which attempt is real, so breadth costs nothing: AES-CBC's
IV only touches the first 16-byte block, which must start with the OMS filler
2F2F, so a wrong IV or layout can never fake a valid frame.

Non-Mode-5 traffic (Mode 7, the Extended Link Layer / AES-CTR, and compact
frames) is recognised and reported by the classifier even though the
key-guessing workflow does not decode it, so the tool stays useful as a general
wM-Bus scanner and not just a single-vendor decoder.
"""

import csv
import datetime
import os

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

# DIF data lengths per EN 13757-3. 0x0D = variable length (LVAR byte follows).
DIF_LEN = {0x0: 0, 0x1: 1, 0x2: 2, 0x3: 3, 0x4: 4, 0x5: 4,
           0x6: 6, 0x7: 8, 0x9: 1, 0xA: 2, 0xB: 3, 0xC: 4, 0xE: 6}

# EN 13757-3 / OMS device (medium) types. Lower-case hex -> human label.
DEV_TYPE = {
    "00": "other", "01": "oil", "02": "electricity", "03": "gas",
    "04": "heat (outlet)", "05": "steam", "06": "warm water",
    "07": "water", "08": "heat cost alloc", "09": "compressed air",
    "0a": "cooling (outlet)", "0b": "cooling (inlet)", "0c": "heat (inlet)",
    "0d": "heat/cool", "0e": "bus/system", "0f": "unknown",
    "10": "irrigation", "11": "water logger", "12": "gas logger",
    "13": "heat/cool logger", "14": "gas conv", "15": "hot water",
    "16": "cold water", "17": "dual water", "18": "pressure",
    "19": "a/d converter", "1a": "smoke detector", "1b": "room sensor",
    "1c": "gas detector", "1d": "reserved", "20": "breaker (el.)",
    "21": "valve", "22": "reserved", "25": "customer unit", "28": "waste water",
    "29": "garbage", "2a": "reserved", "2b": "reserved",
    "31": "osm comm", "32": "unidirect. repeater", "33": "bidirect. repeater",
    "37": "radio converter (system)", "38": "radio converter (meter)",
    "43": "heat meter (sys)", "62": "hca (sys)",
}

# FLAG manufacturer codes (3 letters) -> vendor name. Display only; a missing or
# wrong entry never affects decryption. Kept broad so the collector/stats show
# real names across vendors instead of raw codes. Source: DLMS FLAG register and
# the wmbusmeters manufacturer list.
MFCT_NAMES = {
    "QDS": "Qundis", "LUG": "Landis+Gyr", "LGB": "Landis+Gyr", "KAM": "Kamstrup",
    "TCH": "Techem", "DME": "Diehl Metering", "HYD": "Diehl/Hydrometer",
    "SEN": "Sensus", "SEO": "Sensus", "EFE": "Engelmann", "ENG": "Engelmann",
    "SON": "Sontex", "ELS": "Elster", "ELV": "Elster", "ITW": "Itron",
    "ITR": "Itron", "ACW": "Itron (Actaris)", "GWF": "GWF", "NZR": "NZR",
    "REL": "Relay", "AMT": "Aquametro/Integra", "INE": "Innotas",
    "BMT": "BMETERS", "MAD": "Maddalena", "AXI": "Axioma", "GAV": "Carlo Gavazzi",
    "EMH": "EMH Metering", "WEP": "Weptech", "ZEN": "Zenner", "ZRI": "Zenner",
    "APT": "Apator", "APA": "Apator", "SAP": "Sappel", "DWZ": "Lorenz",
    "LOR": "Lorenz", "EYE": "Eastron", "KAW": "KAW", "MTR": "Metrona",
    "MEL": "Melody", "SBC": "Saia-Burgess", "TIP": "TIP", "WMB": "wmbusmeters",
    "NPS": "Norm. Power", "DZG": "DZG", "EMU": "EMU", "HTC": "Horstmann",
    "PAD": "PadMess", "RKE": "Viterra/Ista", "IST": "ista", "MNS": "MNS",
    "LSE": "LSE", "TCT": "Techem", "GTE": "GTE", "FIN": "Finder",
}

# Bytes that end the record list: idle filler, and 0x00/0xFF padding.
RECORD_END = (0x2F, 0x00, 0xFF)

# Encryption/transport classes reported by classify_encryption. Only the plain
# and aesN (Mode 5) CI layouts feed the decryption path; the rest are reported
# so foreign traffic is visible even when the toolkit cannot decode it.
CI_WRAPPER = 0x78            # vendor wrapper (Qundis), AES-CBC behind 0D FF 5F
CI_ELL = (0x8C, 0x8D, 0x8E, 0x8F)   # Extended Link Layer (AES-CTR when secured)
CI_COMPACT = 0x79           # compact frame, format signature only, no header
# Short (4-byte) and long (12-byte) TPL headers, both transport directions.
# 0x5A/0x5B mirror 0x7A/0x72 for the response direction with the same layout.
CI_TPL_SHORT = (0x7A, 0x5A)
CI_TPL_LONG = (0x72, 0x5B)


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


def mfct_name(code):
    """Vendor name for a FLAG code, or the code itself when unknown."""
    return MFCT_NAMES.get(code, code)


def parse_frame(frame):
    """Split a raw telegram into header fields. Returns a dict or None on junk."""
    hx = clean_hex(frame)
    if len(hx) < 22 or any(c not in "0123456789ABCDEF" for c in hx):
        return None
    ci = hx[20:22]
    code = mfct_code(hx[4:8])
    return {
        "hex": hx,
        "length": int(hx[0:2], 16),
        "mfct": code,
        "mfct_name": mfct_name(code),
        "id": swap_id(hx[8:16]),
        "version": hx[16:18],
        "dev_type": DEV_TYPE.get(hx[18:20].lower(), hx[18:20]),
        "ci": ci,
        "bytes": len(hx) // 2,
        "encrypted": classify_encryption(hx, ci),
    }


def _config_mode(hx, cfg_at):
    """Read the OMS config-word encryption mode at hex offset cfg_at, or None."""
    if cfg_at is None or len(hx) < cfg_at + 4:
        return None
    raw = hx[cfg_at:cfg_at + 4]
    try:
        return (int(raw[2:4] + raw[0:2], 16) >> 8) & 0x0F
    except ValueError:
        return None


def classify_encryption(hx, ci):
    """Transport / encryption class of a telegram.

    'plain'  cleartext application layer (Mode 0)
    'aesN'   TPL Security Mode N (aes5 = AES-CBC, aes7 = AES-CBC + key deriv.)
    'wrap'   vendor wrapper (CI 0x78), AES-CBC behind the 0D FF 5F marker
    'ell'    Extended Link Layer (CI 0x8C-0x8F), AES-CTR when secured
    'compact' compact frame (CI 0x79), needs the matching format telegram
    '?'      unknown / not classified
    """
    try:
        ci_b = int(ci, 16)
    except ValueError:
        return "?"
    if ci_b == CI_WRAPPER:
        return "wrap"
    if ci_b in CI_ELL:
        return "ell"
    if ci_b == CI_COMPACT:
        return "compact"
    # short TPL header: config word right after CI + ACC + status (hex offset 26)
    if ci_b in CI_TPL_SHORT:
        mode = _config_mode(hx, 26)
        return "plain" if mode == 0 else (f"aes{mode}" if mode is not None else "?")
    # long TPL header: config word at hex offset 42
    if ci_b in CI_TPL_LONG:
        mode = _config_mode(hx, 42)
        return "plain" if mode == 0 else (f"aes{mode}" if mode is not None else "?")
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
    Kept for backwards compatibility; cbc_layouts() covers more cases.
    """
    ci = b[10]
    if ci == 0x72 and len(b) > 23:
        return b[15:17] + b[11:15] + b[17:19], b[19], b[23:]
    if ci == 0x7A and len(b) > 15:
        return b[2:10], b[11], b[15:]
    return None, None, None


def build_iv(addr, access):
    """Mode-5 IV: M field(2) + id(4) + version(1) + type(1) + 8x access byte."""
    return (addr + bytes([access]) * 8 + b"\x00" * 16)[:16]


def cbc_layouts(b):
    """Yield (addr, access, ciphertext) AES-CBC attempts for one raw frame.

    Covers the CI-0x78 vendor wrapper, the short TPL header (CI 0x7A and kin)
    and the long TPL header (CI 0x72 and kin). For the long header both the TPL
    address and the link-layer address are offered as IV material, since relayed
    or gateway frames differ on which one seeds the IV. Every attempt is checked
    by the caller, so offering a few extra never risks a false positive: in CBC
    the IV only affects the first 16-byte block, which must decrypt to 2F2F.
    """
    ci = b[10]
    ll = b[2:10]                                   # M(2)+id(4)+ver(1)+type(1)
    if ci == CI_WRAPPER:
        cipher, access = find_wrap_blob(b)
        if cipher:
            yield ll, access, cipher
        # some wrappers keep the ciphertext at the tail instead
        tail = whole_blocks(b[11:])
        if tail and access is not None:
            yield ll, access, tail
        return
    if ci in CI_TPL_LONG and len(b) > 23:
        cipher = whole_blocks(b[23:])
        access = b[19]
        tpl_addr = b[15:17] + b[11:15] + b[17:19]  # mfct+id+ver+type from TPL
        if cipher:
            yield tpl_addr, access, cipher
            yield ll, access, cipher
        return
    if ci in CI_TPL_SHORT and len(b) > 15:
        cipher = whole_blocks(b[15:])
        if cipher:
            yield ll, b[11], cipher
        return


def decrypt_candidates(frame, key):
    """Yield every plaintext produced by trying key across the known layouts."""
    if not HAVE_CRYPTO:
        raise RuntimeError("python3-cryptography is missing")
    b = bytes.fromhex(clean_hex(frame))
    if len(b) < 12:
        return
    seen = set()
    for addr, access, cipher in cbc_layouts(b):
        if access is None or not cipher:
            continue
        tag = (bytes(addr), access, len(cipher))
        if tag in seen:
            continue
        seen.add(tag)
        try:
            dec = Cipher(algorithms.AES(key),
                         modes.CBC(build_iv(addr, access))).decryptor()
            yield dec.update(cipher) + dec.finalize()
        except Exception:
            continue


def decrypt_frame(frame, key):
    """Decrypt a frame with key. Returns the first valid plaintext, and if none
    validates the first attempt (so callers can run their own check), or None."""
    first = None
    for plain in decrypt_candidates(frame, key):
        if first is None:
            first = plain
        if looks_valid(plain):
            return plain
    return first


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


# ---------------------------------------------------------------- Plain dates

def plain_app_bytes(frame):
    """Application-layer record bytes of a *plain* CI-72/CI-7A telegram.

    Same offsets as the Mode-5 ciphertext, but here the bytes are already the
    cleartext DIF/VIF records (mode 0). Returns b"" when the layout is unknown.
    """
    b = bytes.fromhex(clean_hex(frame))
    if len(b) < 12:
        return b""
    ci = b[10]
    if ci == 0x72 and len(b) > 23:
        return b[23:]
    if ci == 0x7A and len(b) > 15:
        return b[15:]
    return b""


def _decode_type_g(d):
    """EN 13757-3 type G date (2 bytes, little-endian) -> datetime.date."""
    if len(d) < 2:
        return None
    b0, b1 = d[0], d[1]
    day = b0 & 0x1F
    month = b1 & 0x0F
    year = 2000 + (((b0 & 0xE0) >> 5) | ((b1 & 0xF0) >> 1))
    if not (1 <= day <= 31 and 1 <= month <= 12 and 2000 <= year <= 2099):
        return None
    try:
        return datetime.date(year, month, day)
    except ValueError:
        return None


def _decode_type_f(d):
    """EN 13757-3 type F date+time (4 bytes, little-endian) -> datetime."""
    if len(d) < 4:
        return None
    b0, b1, b2, b3 = d[0], d[1], d[2], d[3]
    if b1 & 0x80:                       # "invalid" flag set
        return None
    minute = b0 & 0x3F
    hour = b1 & 0x1F
    day = b2 & 0x1F
    month = b3 & 0x0F
    year = 2000 + (((b2 & 0xE0) >> 5) | ((b3 & 0xF0) >> 1))
    if not (0 <= minute < 60 and 0 <= hour < 24 and
            1 <= day <= 31 and 1 <= month <= 12 and 2000 <= year <= 2099):
        return None
    try:
        return datetime.datetime(year, month, day, hour, minute)
    except ValueError:
        return None


def extract_dates(frame):
    """Dates/datetimes carried in a plain telegram's data records.

    Walks the cleartext DIF/VIF records and decodes every type G date
    (VIF 0x6C) and type F date+time (VIF 0x6D). The plain Qundis telegram
    (CI 72, mode 0) carries the commissioning / billing date this way, which
    keygen can turn into date-derived key candidates.
    """
    out = []
    app = plain_app_bytes(frame)
    if not app:
        return out
    for dif, vifs, data in iter_records(app):
        base = (vifs[0] & 0x7F) if vifs else 0
        if base == 0x6C:
            dt = _decode_type_g(data)
        elif base == 0x6D:
            dt = _decode_type_f(data)
        else:
            dt = None
        if dt is not None:
            out.append(dt)
    return out
