# wmbus-toolkit

Collect, archive and decrypt wireless M-Bus telegrams from
[wmbusmeters](https://github.com/wmbusmeters/wmbusmeters). Dedupes raw
telegrams into a CSV, builds AES key candidate lists (defaults plus
id/serial-derived), and validates keys against the collected traffic.
Tested with Qundis Q water/heat 5.5. No meter data is hardcoded; everything
comes from `meters.conf` or the command line.

## Workflow

1. `wmbus-collect` gathers raw telegrams deduplicated into a CSV, even while no
   key is available yet. This builds a history that can be decoded retroactively
   later.
2. `wmbus-keygen` builds candidate lists: generic defaults plus keys derived
   from id and serial number.
3. `wmbus-keycheck` tests keys against the collected telegrams. The test is
   two-stage and does not report random hits.

Important: a properly assigned AES-128 key is 16 bytes of randomness. It cannot
be generated and cannot be brute-forced. The candidate list only catches
defaults and sloppily derived keys. The reliable route to the key remains the
metering service provider / Qundis.

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

`meters.conf`, `keys/` and `*.csv` are listed in `.gitignore`, so real meter
ids, serials and collected traffic stay out of the repository.

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

Build candidates:

    wmbus-keygen --meters meters.conf --out keys/
    # or a single meter:
    wmbus-keygen --id 12345678 --serial 1234567890 --name MeterA --out keys/

Check:

    bash keys/run.sh /var/lib/wmbusmeters/telegrams.csv
    # or targeted:
    wmbus-keycheck --csv .../telegrams.csv --id 12345678 --key <32hex>

If a key matches, decode the whole history:

    wmbus-keycheck --csv .../telegrams.csv --id 12345678 \
                   --key <32hex> --decode-all --out plaintext.csv

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
