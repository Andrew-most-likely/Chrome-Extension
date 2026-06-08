#!/bin/bash
# Packages the extension for Chrome Web Store submission.
# Run from the chrome extension root directory:
#   bash store-assets/package.sh
#
# Requires: zip (available in Git Bash on Windows)
# Output: phishing-detector-v<version>.zip in the current directory

set -e

VERSION=$(grep '"version"' manifest.json | grep -oP '"\d+\.\d+\.\d+"' | tr -d '"')
OUTPUT="phishing-detector-v${VERSION}.zip"

echo "Building $OUTPUT ..."

zip -r "$OUTPUT" . \
  --exclude "*.git*" \
  --exclude "config.js" \
  --exclude "store-assets/*" \
  --exclude "site/*" \
  --exclude "hello.html" \
  --exclude "hello_extensions.png" \
  --exclude "generate-icons.html" \
  --exclude "*.zip" \
  --exclude "*.sh"

echo "Done. Submit $OUTPUT to:"
echo "https://chrome.google.com/webstore/devconsole"
