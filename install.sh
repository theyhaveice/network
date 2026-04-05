#!/bin/bash

if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "This script only runs on macOS."
    exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
   echo "This script must be run with sudo."
   exit 1
fi

echo "Downloading network v0.1.0..."

URL="https://github.com/theyhaveice/network/releases/download/v0.1.0-alpha/network-v0.1.0-macos.zip"
ZIP_FILE="/tmp/network-v0.1.0-macos.zip"
TMP_DIR="/tmp/network_install"

mkdir -p "$TMP_DIR"

curl -L -o "$ZIP_FILE" "$URL"

rm -f "$TMP_DIR"/.DS_Store
rm -f "$TMP_DIR"/._*

unzip -q "$ZIP_FILE" -d "$TMP_DIR"

mv "$TMP_DIR/network" /usr/local/bin/network

rm -rf "$TMP_DIR"
rm -f "$ZIP_FILE"

echo "network v0.1.0 installed successfully!"
echo "You can run it using: network"
