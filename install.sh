#!/bin/bash
# Installs the wmbus-toolkit to /opt/wmbus-toolkit and creates symlinks.
#
#   git clone https://github.com/3DJupp/wmbus-toolkit.git
#   sudo bash wmbus-toolkit/install.sh
#
# If the repository was cloned directly to /opt/wmbus-toolkit, nothing is
# copied and a later `git pull` updates the installation in place.
set -e

DEST=/opt/wmbus-toolkit
SRC="$(cd "$(dirname "$0")" && pwd)"
FILES="wmbuslib.py wmbus-collect.py wmbus-keygen.py wmbus-keycheck.py meters.conf.example README.md"

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo bash install.sh)"
  exit 1
fi

if ! python3 -c "import cryptography" 2>/dev/null; then
  echo "Note: python3-cryptography is missing. Install with:"
  echo "  apt install python3-cryptography"
fi

if [ "$SRC" != "$DEST" ]; then
  mkdir -p "$DEST"
  for f in $FILES; do
    cp "$SRC/$f" "$DEST/"
  done
fi

# do not overwrite an existing meters.conf
if [ ! -f "$DEST/meters.conf" ]; then
  cp "$DEST/meters.conf.example" "$DEST/meters.conf"
  echo "Template copied to $DEST/meters.conf - please edit."
fi

for tool in wmbus-collect wmbus-keygen wmbus-keycheck; do
  chmod +x "$DEST/$tool.py"
  ln -sf "$DEST/$tool.py" "/usr/local/bin/$tool"
done

echo "Installed to $DEST, commands: wmbus-collect, wmbus-keygen, wmbus-keycheck"
