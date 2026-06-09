// ============================================================
// PAYMENT REDIRECT DETECTOR - Content Script (ISOLATED world)
// Listens for events dispatched by interceptor.js (MAIN world)
// and watches for dynamically injected inline scripts.
// ============================================================

// Re-validate payment URLs in isolated world to prevent spoofed events.
// Page scripts can dispatch __phishing_redirect__ with arbitrary data, so we
// independently confirm the redirectUrl matches a known payment domain before
// forwarding to the background. Rate-limited to one report per page load.
const PAYMENT_DOMAIN_REGEX_ISOLATED = /paypal\.com|stripe\.com|venmo\.com|cash\.app|cashapp\.com|coinbase\.com|zelle\.com|blockchain\.com|kraken\.com|binance\.com|wise\.com|transferwise\.com|moneygram\.com|westernunion\.com/i;

let redirectReported = false;

// ---- Listen for redirect events from interceptor.js ----
window.addEventListener("__phishing_redirect__", (e) => {
  if (redirectReported) return;  // one report per page load - prevents DoS via repeated events

  const redirectUrl = e.detail && e.detail.redirectUrl;

  // Reject events whose redirectUrl is not an actual payment domain URL.
  // This prevents page scripts from spoofing the event to trigger warnings
  // for arbitrary URLs.
  if (!redirectUrl || !PAYMENT_DOMAIN_REGEX_ISOLATED.test(redirectUrl)) return;

  redirectReported = true;

  chrome.runtime.sendMessage(
    {
      type: "PAYMENT_REDIRECT_DETECTED",
      sourceUrl: window.location.href,
      redirectUrl,
      detail: `This page tried to redirect you to: ${redirectUrl}`,
    },
    (response) => {
      if (chrome.runtime.lastError) {
        console.warn("[VantaSecurity]", chrome.runtime.lastError.message);
      }
    }
  );
});

// ---- Watch for dynamically injected inline scripts ----
// Covers scripts added via XHR/fetch callbacks after page load.
// interceptor.js handles Location overrides; this catches script
// tags that contain payment redirect patterns before they execute.

const PAYMENT_DOMAIN_REGEX = new RegExp(
  [
    "paypal\\.com", "stripe\\.com", "venmo\\.com", "cash\\.app",
    "cashapp\\.com", "coinbase\\.com", "zelle\\.com", "blockchain\\.com",
    "kraken\\.com", "binance\\.com", "wise\\.com", "transferwise\\.com",
    "moneygram\\.com", "westernunion\\.com",
  ].join("|"),
  "i"
);
const REDIRECT_PATTERN = /window\.location|location\.href|location\.replace|location\.assign/;

const observer = new MutationObserver((mutations) => {
  if (redirectReported) return;  // one report per page load - shared with event listener
  for (const mutation of mutations) {
    for (const node of mutation.addedNodes) {
      if (node.nodeName === "SCRIPT" && !node.src) {
        const text = node.textContent || "";
        if (REDIRECT_PATTERN.test(text) && PAYMENT_DOMAIN_REGEX.test(text)) {
          redirectReported = true;
          observer.disconnect();
          chrome.runtime.sendMessage(
            {
              type: "PAYMENT_REDIRECT_DETECTED",
              sourceUrl: window.location.href,
              redirectUrl: window.location.href,
              detail: text.slice(0, 120).replace(/\s+/g, " ").trim(),
            },
            (response) => {
              if (chrome.runtime.lastError) return;
            }
          );
          return;
        }
      }
    }
  }
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true,
});
