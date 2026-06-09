# Security Policy

## Supported versions

Only the latest published version of Vanta Security is actively maintained.

## Reporting a vulnerability

If you find a security vulnerability including bypass techniques, data leaks, or unsafe API handling **please do not open a public issue.**

Report it privately by emailing the maintainer directly. You can find contact info on the Chrome Web Store listing or via GitHub.

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- The version/commit where you found it

You can expect an acknowledgment within a few days. If the issue is confirmed, a fix will be prioritized and you'll be credited in the release notes (unless you prefer otherwise).

## Scope

Things we consider in scope:
- Bypassing the phishing/malware block without using the intended bypass flow
- Leaking the proxy secret or API key through extension behavior
- Cross-origin data exposure via content scripts or the warning page
- Malicious sites being whitelisted or bypass-listed without user intent

Out of scope:
- Issues that require physical access to the user's machine
- Vulnerabilities in Google Safe Browsing itself
- The Vercel proxy being rate-limited or overwhelmed
