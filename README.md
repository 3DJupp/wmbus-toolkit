# wmbus-toolkit

Collect, archive and decrypt wireless M-Bus telegrams from
[wmbusmeters](https://github.com/wmbusmeters/wmbusmeters). Dedupes raw
telegrams into a CSV, builds one combined AES key candidate file (published
test vectors plus id / serial / date-derived keys), and validates keys against
the collected traffic in a single run over all meters.
Tested with Qundis Q water/heat 5.5. No meter data is hardcoded; everything
comes from `meters.conf` or the command line.

## Workflow

1. `wmbus-collect` gathers raw telegrams deduplicated into a CSV, even while no
   key is available yet. This builds a history that can be decoded retroactively
   later.
2. `wmbus-keygen` writes a single combined candidate file: generic defaults
   (published AES / wM-Bus test vectors, byte patterns, ASCII words) plus keys
   derived from id, serial, model and install date. Every line carries a scope
   prefix so keycheck knows which key belongs to which meter.
3. `wmbus-keycheck` tests keys against the collected telegrams, in one run over
   all meters. Each meter is tested with its own scoped keys plus the generic
   `all` keys. The match test is two-stage and does not report random hits.

So the whole flow is two commands, no `run.sh` wrapper:

    wmbus-keygen  --meters meters.conf --from-csv telegrams.csv --out candidates.txt
    wmbus-keycheck --csv telegrams.csv --keyfile candidates.txt

Honest framing: this is a **default- and derivation-test, not an attack on
AES**. A properly assigned AES-128 key is 16 bytes of randomness - it cannot be
generated and cannot be brute-forced. The candidate list only catches keys left
at a default or lazily derived from id / serial / date (for example the SHA-256
of the serial number, truncated to 16 bytes). The realistic hit probability is
small, but the effort is negligible, so it is worth a try before falling back to
the only reliable route: the metering service provider / Qundis.

## Installation

    apt install python3-cryptography
    git clone https://github.com/3DJupp/wmbus-toolkit.git
    sudo bash wmbus-toolkit/install.sh   # copies to /opt/wmbus-toolkit, symlinks in /usr/local/bin

Or clone straight into the install location, so `git pull` updates it in place:

    sudo git clone https://github.com/3DJupp/wmbus-toolkit.git /opt/wmbus-toolkit
    sudo bash /opt/wmbus-toolkit/install.sh

## Updating

    cd wmbus-toolkit && git pull
    sudo bash install.sh      # re-copies the files, keeps your meters.conf

## Configuration

    cp meters.conf.example meters.conf
    # fill meters.conf with your own meters

`meters.conf`, `keys/`, `candidates.txt` and `*.csv` are listed in
`.gitignore`, so real meter ids, serials and collected traffic stay out of the
repository.

## Usage

Collect, importing existing logs:

    wmbus-collect --csv /var/lib/wmbusmeters/telegrams.csv \
                  --meters meters.conf \
                  --import /var/log/wmbusmeters/wmbusmeters.log*

Keep collecting live (e.g. as a systemd service):

    wmbus-collect --csv /var/lib/wmbusmeters/telegrams.csv \
                  --meters meters.conf --tail /var/log/wmbusmeters/wmbusmeters.log

Statistics:

    wmbus-collect --csv /var/lib/wmbusmeters/telegrams.csv --stats

Build candidates (one combined file):

    wmbus-keygen --meters meters.conf --from-csv /var/lib/wmbusmeters/telegrams.csv \
                 --out candidates.txt
    # or a single meter:
    wmbus-keygen --id 12345678 --serial 1234567890 --name MeterA \
                 --installed 2021-03-15 --out candidates.txt

`--from-csv` decodes the install / billing date out of each meter's plain
telegrams, so keygen builds date-derived candidates on its own. `--install-date`
sets a global fallback date; the per-meter `installed=` field in meters.conf
overrides it. keygen prints a count per category and validates every key to
exactly 32 hex characters before writing.

Check (all meters in one run):

    wmbus-keycheck --csv /var/lib/wmbusmeters/telegrams.csv --keyfile candidates.txt
    # or targeted:
    wmbus-keycheck --csv .../telegrams.csv --id 12345678 --key <32hex>

Self-test (encrypts a frame with a candidate key, must find it as a MATCH via
the combined file, and must reject a wrong key):

    wmbus-keycheck --selftest --keyfile candidates.txt

If a key matches, decode the whole history:

    wmbus-keycheck --csv .../telegrams.csv --id 12345678 \
                   --key <32hex> --decode-all --out plaintext.csv

### Candidate file format

Each line is `<scope>:<label>=<32 hex>`:

    all:repeat_00=00000000000000000000000000000000
    all:oms_annexN_profA=0102030405060708090A0B0C0D0E0F11
    68347172:date_bcd_x4=20210315202103152021031520210315
    68347172:ser_ascii_sha256=...

`scope=all` keys are tried against every meter; `scope=<id>` keys only against
that meter. Lines without a scope (`label=hex`) are read as `all`, so old
candidate files still work. Dedup is global: no key is tested twice against the
same meter.

Generic (`all`) categories: single repeated bytes, the NIST AESAVS KAT vectors
(KeySbox and VarKey for AES-128, plus the FIPS-197 / SP 800-38A example key),
published wM-Bus / OMS example keys (OMS Annex N, the wmbusmeters demo key),
hex-culture constants (DEADBEEF & co.), Fibonacci / prime / stepping byte
sequences, manufacturer names, common passwords and installer shorthands.

Per-meter (`<id>`) categories are built by a small combinator from the meter's
raw sources (id, id little-endian, serial ASCII/BCD/int, model digits, and every
date variant): pad / left-pad / repeat, pairwise concatenation in both orders,
date XOR id, and MD5 / SHA-1 / SHA-256 of the source truncated to 16 bytes.

Date variants cover ASCII (`YYYYMMDD`, `DDMMYYYY`, `YYYY-MM-DD`, `DD.MM.YYYY`),
BCD, and Unix timestamp (big/little-endian), plus date+time and time-only forms
when a time is known.

### Legacy per-file layout

The old layout (`candidates_generic.txt`, one file per meter, and a `run.sh`) is
no longer needed but still available:

    wmbus-keygen --meters meters.conf --out candidates.txt --legacy-runner keys/
    bash keys/run.sh /var/lib/wmbusmeters/telegrams.csv

## systemd service for continuous collection

    cat > /etc/systemd/system/wmbus-collect.service << 'UNIT'
    [Unit]
    Description=wmbus telegram collector
    After=wmbusmeters.service

    [Service]
    ExecStart=/usr/local/bin/wmbus-collect \
      --csv /var/lib/wmbusmeters/telegrams.csv \
      --meters /opt/wmbus-toolkit/meters.conf \
      --tail /var/log/wmbusmeters/wmbusmeters.log
    Restart=always
    RestartSec=10

    [Install]
    WantedBy=multi-user.target
    UNIT
    systemctl daemon-reload && systemctl enable --now wmbus-collect

## Telegram structure (Qundis Q water/heat 5.5)

Each meter emits three telegram classes:

| Class | Content |
|-------|---------|
| plain (CI 72, mode 0) | date and model version only |
| aes5  (CI 72, mode 5) | encrypted, standard OMS |
| wrap  (CI 78)         | Qundis wrapper, encrypted, carries the readings |

The wrapper payload sits behind the record marker `0D FF 5F`: a length byte,
then 5 prefix bytes (`00 82 <2B counter> <access>`), then the AES-CBC ciphertext
as a multiple of 16. The Mode-5 IV is M-field + id + version + type + 8x the
access byte.

## Files

    wmbuslib.py          shared building blocks (config, frame parsing, crypto)
    wmbus-collect.py     collect telegrams
    wmbus-keygen.py      build candidates
    wmbus-keycheck.py    test keys
    meters.conf.example  template with mock data
    install.sh           installer

## License

MIT
