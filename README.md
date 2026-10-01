# wmbus-toolkit

A vendor-neutral Swiss-army-knife for wireless M-Bus / OMS traffic captured with
[wmbusmeters](https://github.com/wmbusmeters/wmbusmeters). It dedupes raw
telegrams into a CSV, decodes device type and manufacturer for any vendor, builds
one combined AES key-candidate file (published test vectors, a broad factory /
default set, plus id / serial / date / manufacturer-derived keys), and validates
keys against the collected traffic in a single run over all meters.

Not tied to one device or one brand: the collector classifies every CI layout it
sees (plain, Mode 5/7, the CI-0x78 vendor wrapper, Extended Link Layer, compact
frames), and decryption tries the short- and long-TPL header layouts with both
the TPL and link-layer IV address, so it decodes standard OMS Mode-5 traffic from
many manufacturers, not just the Qundis Q water/heat 5.5 it was first built on.
No meter data is hardcoded; everything comes from `meters.conf`, the meter's own
telegrams, or the command line.

## Workflow

1. `wmbus-collect` gathers raw telegrams deduplicated into a CSV, even while no
   key is available yet. This builds a history that can be decoded retroactively
   later.
2. `wmbus-keygen` writes a single combined candidate file: generic defaults
   (published AES / wM-Bus test vectors, byte patterns, a broad manufacturer /
   FLAG-code and factory-default set) plus keys derived from id, serial, model,
   install date and the meter's own manufacturer. Every line carries a scope
   prefix so keycheck knows which key belongs to which meter. With
   `--from-csv ... --all-meters` it builds candidates for every meter seen on the
   air, filling in each meter's manufacturer and version from its telegrams.
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
    # every meter seen on the air, manufacturer/version filled in from telegrams:
    wmbus-keygen --from-csv /var/lib/wmbusmeters/telegrams.csv --all-meters \
                 --out candidates.txt
    # or a single meter:
    wmbus-keygen --id 12345678 --serial 1234567890 --name MeterA \
                 --installed 2021-03-15 --out candidates.txt

`--from-csv` decodes the install / billing date out of each meter's plain
telegrams, so keygen builds date-derived candidates on its own. `--install-date`
sets a global fallback date; the per-meter `installed=` field in meters.conf
overrides it. keygen prints a count per category and validates every key to
exactly 32 hex characters before writing.

Already know a key (printed on the meter, supplied by the provider, or found
earlier)? Put it in meters.conf as `key=<32hex>` (or pass `--known-key` for a
single meter). keygen writes it first in that meter's scope, as category
`known`, so it is tried before any guess - and `wmbus-keycheck --meters
meters.conf` picks it up directly, without needing a candidate file at all.

Check (all meters in one run):

    wmbus-keycheck --csv /var/lib/wmbusmeters/telegrams.csv --keyfile candidates.txt
    # known keys from meters.conf, no candidate file needed:
    wmbus-keycheck --csv /var/lib/wmbusmeters/telegrams.csv --meters meters.conf
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
published wM-Bus / OMS example keys (OMS Annex N, the wmbusmeters demo key, the
ascending OMS test keys), hex-culture constants (DEADBEEF & co.), Fibonacci /
prime / stepping byte sequences, a broad set of manufacturer names and 3-letter
FLAG codes across many vendors, common passwords and installer shorthands.

Per-meter (`<id>`) categories: `known` is a key already on file (meters.conf
`key=`), written first and ahead of every guess. The rest are built by a small
combinator from the meter's raw sources (id, id little-endian, serial
ASCII/BCD/int, model digits, the meter's manufacturer name / FLAG code, and
every date variant): pad / left-pad / repeat, pairwise concatenation in both
orders, date XOR id, and MD5 / SHA-1 / SHA-256 of the source truncated to 16
bytes. The manufacturer and version are
read from the meter's own telegrams when not given in `meters.conf`.

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

## Telegram structure and supported layouts

The collector classifies every telegram by its CI byte and reports the class:

| Class     | Meaning |
|-----------|---------|
| `plain`   | cleartext application layer (Mode 0) |
| `aes5`    | TPL Security Mode 5, AES-CBC (standard OMS) |
| `aes7`    | TPL Security Mode 7, AES-CBC with key derivation |
| `wrap`    | vendor wrapper (CI 0x78), AES-CBC behind the `0D FF 5F` marker |
| `ell`     | Extended Link Layer (CI 0x8C-0x8F), AES-CTR when secured |
| `compact` | compact frame (CI 0x79), needs the matching format telegram |

Decryption covers the AES-CBC paths (`aes5` and the CI-0x78 `wrap`). It tries
both the short TPL header (CI 0x7A and kin) and the long TPL header (CI 0x72 and
kin), and for the long header seeds the IV from both the TPL address and the
link-layer address, so relayed or gateway frames decode too. The Mode-5 IV is
M-field + id + version + type + 8x the access byte. Because AES-CBC's IV only
affects the first 16-byte block - which must decrypt to the OMS filler `2F2F` -
trying several layouts never produces a false match.

The `aes7`, `ell` and `compact` classes are recognised and reported (so the tool
is useful as a general scanner across vendors) but not decoded by the
key-guessing workflow: Mode 7 needs the per-message derived key, and the ELL uses
AES-CTR with a different validator.

For reference, the observed Qundis Q water/heat 5.5 wrapper payload sits behind
`0D FF 5F`: a length byte, then 5 prefix bytes (`00 82 <2B counter> <access>`),
then the AES-CBC ciphertext as a multiple of 16.

## Files

    wmbuslib.py          shared building blocks (config, frame parsing, crypto)
    wmbus-collect.py     collect telegrams
    wmbus-keygen.py      build candidates
    wmbus-keycheck.py    test keys
    meters.conf.example  template with mock data
    install.sh           installer

## License

MIT
