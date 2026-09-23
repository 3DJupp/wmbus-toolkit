#!/usr/bin/env python3
"""
Tests for plain-telegram decoding and the insights keygen draws from it.

The fixtures are real Qundis (QDS, CI 72) and Itron (ITW, CI 7A) plain telegrams
with the meter ids swapped for synthetic ones and the Itron water readings
replaced by round synthetic values - the byte structure, VIFs and date encodings
are untouched, so the decoders are exercised exactly as on real traffic without
publishing anyone's meter ids or consumption.

What the plain telegrams reveal (and what these tests lock in):

* Itron water meters (CI 7A) transmit *in the clear* - current and last-period
  volume plus the billing date are readable with no key at all.
* Qundis heat converters (CI 72) send a plain companion frame to their encrypted
  CI 78 wrapper. It carries a fixed reference/commissioning datetime that repeats
  in every telegram (the useful key-derivation seed) next to the current clock
  that changes each time.

Run:  python3 tests/test_plain.py
"""

import csv
import datetime
import importlib.util
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import wmbuslib as wl


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


kg = _load("wmbus_keygen", "wmbus-keygen.py")

# --- fixtures (anonymized, structure preserved) ------------------------------

# Qundis heat converter, id 11223344. Three telegrams sharing the commissioning
# datetime 2025-07-11 07:57 (record 04 ED39), with a changing current clock.
QDS_A = [
    "3C449344443322113F37724433221193443F04C000082004ED3939072B3701FD0C11046D13044D3902FD3CC2010DFF5F0C0008E2FF008006130705FFFC",
    "3C449344443322113F37724433221193443F040000082004ED3939072B3701FD0C11046D1A0C4D3902FD3CC2010DFF5F0C0008E2FF008006130705FFFC",
    "3C449344443322113F37724433221193443F048000082004ED3939072B3701FD0C11046D1B044E3902FD3CC2010DFF5F0C0008E2FF008006130705FFFC",
]
# Qundis heat converter, id 55667788, commissioning 2025-08-19 09:30.
QDS_B = "3C449344887766553F37728877665593443F040000082004ED391E09333801FD0C11046D230B4D3902FD3CC2010DFF5F0C0008E2FF008006130705FFFC"
# Itron water meter, id 66778899. Synthetic readings: current 12.345 m3,
# last period 10.000 m3; billing date 2025-12-31 (record 42 6C).
ITW = "384497269988776600077AEA0000A0041339300000066D3125EA4D3900441310270000426C3F3C047F0000060C027F3F2A0E79000000000000"


def record_value_le(frame, dif_hex, vif_hex):
    """First matching record's data as a little-endian integer, or None."""
    for dif, vifs, data in wl.iter_records(wl.plain_app_bytes(frame)):
        vh = "".join(f"{v:02X}" for v in vifs)
        if f"{dif:02X}" == dif_hex and vh == vif_hex:
            return int.from_bytes(data, "little")
    return None


class TestPlainHeaders(unittest.TestCase):

    def test_qds_header(self):
        info = wl.parse_frame(QDS_A[0])
        self.assertEqual(info["id"], "11223344")
        self.assertEqual(info["mfct"], "QDS")
        self.assertEqual(info["dev_type"], "radio converter")
        self.assertEqual(info["ci"], "72")
        self.assertEqual(info["encrypted"], "plain")

    def test_itw_header(self):
        info = wl.parse_frame(ITW)
        self.assertEqual(info["id"], "66778899")
        self.assertEqual(info["mfct"], "ITW")
        self.assertEqual(info["dev_type"], "water")
        self.assertEqual(info["ci"], "7A")
        self.assertEqual(info["encrypted"], "plain")


class TestPlainInsights(unittest.TestCase):

    def test_itw_readings_are_cleartext(self):
        # no key needed: the water meter hands out its readings in the clear
        self.assertEqual(record_value_le(ITW, "04", "13"), 12345)   # current, l
        self.assertEqual(record_value_le(ITW, "44", "13"), 10000)   # last period

    def test_itw_billing_date(self):
        self.assertIn(datetime.date(2025, 12, 31), wl.extract_dates(ITW))

    def test_itw_sixbyte_datetime_not_misdecoded(self):
        # only the 2-byte type-G billing date decodes; the 6-byte current clock
        # (06 6D) must not be mis-read from the wrong bytes
        self.assertEqual(wl.extract_dates(ITW), [datetime.date(2025, 12, 31)])

    def test_qds_commissioning_datetime(self):
        dates = wl.extract_dates(QDS_A[0])
        self.assertIn(datetime.datetime(2025, 7, 11, 7, 57), dates)
        self.assertEqual(wl.extract_dates(QDS_B)[0],
                         datetime.datetime(2025, 8, 19, 9, 30))

    def test_qds_commissioning_is_stable_current_clock_varies(self):
        commissioning = {wl.extract_dates(h)[0] for h in QDS_A}
        currents = {wl.extract_dates(h)[1] for h in QDS_A}
        self.assertEqual(commissioning, {datetime.datetime(2025, 7, 11, 7, 57)})
        self.assertEqual(len(currents), len(QDS_A))   # each telegram differs


class TestDateFieldGating(unittest.TestCase):
    """type G is 2 bytes, type F 4 bytes; other lengths must be ignored."""

    def _dates(self, app_hex):
        # minimal CI-7A short header: data records start at byte 15
        header = bytes([0x2E, 0x44, 0x24, 0x24, 0x23, 0x23, 0x23, 0x23,
                        0x01, 0x07, 0x7A, 0x00, 0x00, 0x00, 0x00])
        return wl.extract_dates(header.hex() + app_hex)

    def test_type_g_2_bytes(self):
        self.assertEqual(self._dates("026C3F3C"), [datetime.date(2025, 12, 31)])

    def test_type_f_4_bytes(self):
        self.assertEqual(self._dates("046D07082C38"),
                         [datetime.datetime(2025, 8, 12, 8, 7)])

    def test_six_byte_date_time_ignored(self):
        self.assertEqual(self._dates("066D3125EA4D3900"), [])


class TestKeygenStableDates(unittest.TestCase):

    def _csv(self, telegrams):
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        with open(path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["id", "ci", "enc_mode", "telegram"])
            for hx in telegrams:
                info = wl.parse_frame(hx)
                w.writerow([info["id"], info["ci"], info["encrypted"], hx])
        return path

    def test_stable_date_wins_over_current_clock(self):
        path = self._csv(QDS_A)
        try:
            per = kg.collect_csv_dates(path)
        finally:
            os.unlink(path)
        # only the recurring commissioning datetime survives the stable filter
        self.assertEqual(per["11223344"],
                         [datetime.datetime(2025, 7, 11, 7, 57)])

    def test_single_telegram_keeps_all_dates(self):
        path = self._csv([QDS_B])
        try:
            per = kg.collect_csv_dates(path)
        finally:
            os.unlink(path)
        self.assertEqual(per["55667788"][0],
                         datetime.datetime(2025, 8, 19, 9, 30))


class TestKeygenDateDerivation(unittest.TestCase):

    def test_commissioning_date_becomes_candidates(self):
        d = datetime.datetime(2025, 7, 11, 7, 57)
        cand = kg.meter_candidates({"id": "11223344"}, [d])
        # date in BCD, repeated to 16 bytes, is a concrete derived candidate
        self.assertEqual(cand["date_bcd_x4"], bytes.fromhex("20250711" * 4))
        self.assertEqual(cand["date_ymd_pad0"], kg.fit16(b"20250711"))
        # with a time present, the date+time form is derived too
        self.assertIn("date_ymdhm_pad0", cand)


if __name__ == "__main__":
    unittest.main(verbosity=2)
