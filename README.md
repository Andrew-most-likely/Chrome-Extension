# Phishing Detector

A Chrome extension that provides real-time protection against phishing, malware, payment redirect fraud, and credential-harvesting forms.

## Features

- **Google Safe Browsing** - Every URL checked against Google's threat database (malware, phishing, unwanted software)
- **URL heuristics** - Catches dangerous URLs before DNS resolves: bare IPs, lookalike domains (paypa1.com), punycode, high-risk TLDs (.tk/.ml/.ga), brand-in-subdomain attacks, fake TLDs in the middle of hostnames, and the @ trick
- **Payment redirect interception** - Hooks `window.location` to block silent redirects to PayPal, Stripe, Coinbase, etc.
- **Form hijack detection** - Scans login forms whose action submits credentials to a foreign domain
- **Session bypass list** - 24-hour auto-expiring bypasses for sites you choose to visit anyway
- **Permanent whitelist** - Domains you trust are never checked again
- **Block history** - Full log with threat type labels and timestamps in the popup

## Project structure

```
chrome extension/
|- background.js          # Service worker: heuristics, Safe Browsing, bypass/whitelist logic
|- content.js             # Injected into pages (ISOLATED world)
|- interceptor.js         # Payment redirect hook (MAIN world)
|- form-scanner.js        # Cross-origin form action scanner (ISOLATED world)
|- warning.html/js        # Threat warning page shown on block
|- popup.html/js          # Extension popup: tally, history, bypass and whitelist management
|- manifest.json
|- config.js              # API key and proxy secret (gitignored)
|- icons/                 # Extension icons (16, 32, 48, 128 px)
|- extension-tests/       # Local test pages for every detection type
|- store-assets/          # Chrome Web Store listing copy and packaging script
|- site/                  # Vercel proxy (forwards to Google Safe Browsing API)
```

## Setup

1. Clone the repo.
2. Copy `config.js.example` to `config.js` (or create it) and fill in your Safe Browsing API key and proxy secret:

```js
const CONFIG = {
  API_KEY: "YOUR_SAFE_BROWSING_KEY",
  PROXY_URL: "https://chrome-extension-nu-eight.vercel.app/api/check",
  PROXY_SECRET: "YOUR_PROXY_SECRET",
};
```

3. Load the extension in Chrome: `chrome://extensions` > Enable Developer mode > Load unpacked > select this folder.

## Proxy / Vercel

The `site/` directory is a Vercel serverless function that proxies requests to the Google Safe Browsing API. The `DETECTOR_TOKEN` environment variable must be set in Vercel to match the `PROXY_SECRET` in `config.js`. The token is validated server-side and never exposed to the client.

## Packaging for the Chrome Web Store

```bash
bash store-assets/package.sh
```

Output: `phishing-detector-v<version>.zip` - ready to upload at https://chrome.google.com/webstore/devconsole

## Links

- Extension website / privacy policy: https://chrome-extension-nu-eight.vercel.app
- Chrome Web Store listing copy: `store-assets/listing.txt`
