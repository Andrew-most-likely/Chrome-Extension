#!/bin/bash
# Packages the extension for Chrome Web Store submission.
# Run from the chrome extension root directory:
#   bash store-assets/package.sh
#
# Requires: zip (available in Git Bash on Windows)
# Output: vanta-security-v<version>.zip in the current directory

set -e

VERSION=$(grep '"version"' extension/manifest.json | grep -oP '"\d+\.\d+\.\d+"' | tr -d '"')
OUTPUT="vanta-security-v${VERSION}.zip"

echo "Building $OUTPUT ..."

zip -r "$OUTPUT" extension/ \
  --exclude "extension/config.js" \
  --exclude "*.zip"

echo "Done. Submit $OUTPUT to:"
echo "https://chrome.google.com/webstore/devconsole"
