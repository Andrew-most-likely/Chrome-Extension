# Contributing to Vanta Security

Thanks for your interest in contributing!

## Getting started

1. Fork the repo and clone it locally.
2. Follow the setup steps in `README.md` (you'll need a Google Safe Browsing API key and a Vercel deployment for the proxy).
3. Load the `Vanta/` folder as an unpacked extension in Chrome (`chrome://extensions` → Developer mode → Load unpacked).

## What to work on

- Bug reports and fixes are always welcome   open an issue first to describe what you found.
- New heuristics for URL or form detection are a good fit; keep them in `background.js` or `form-scanner.js` as appropriate.
- UI improvements to `popup.html/js` or `warning.html/js`.
- Test pages under `docs/` that cover detection gaps.

## Guidelines

- Keep changes focused one fix or feature per PR.
- Test against the existing pages in `docs/` before submitting.
- Don't commit `config.js` it's gitignored for a reason.
- Match the existing code style (no build step, plain ES modules, MV3 service worker constraints).

## Submitting a PR

- Write a clear title and describe what changed and why.
- Link any related issue in the PR description.
- PRs that break the test pages in `docs/` won't be merged.
