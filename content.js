// ============================================================
// PAYMENT REDIRECT DETECTOR — Content Script (ISOLATED world)
// Listens for events dispatched by interceptor.js (MAIN world)
// and watches for dynamically injected inline scripts.
// ============================================================

// ---- Listen for redirect events from interceptor.js ----
window.addEventListener("__phishing_redirect__", (e) => {
  chrome.runtime.sendMessage(
    {
      type: "PAYMENT_REDIRECT_DETECTED",
      sourceUrl: window.location.href,
      redirectUrl: e.detail.redirectUrl,
      detail: `This page tried to redirect you to: ${e.detail.redirectUrl}`,
    },
    (response) => {
      if (chrome.runtime.lastError) {
        console.warn("[PhishingDetector]", chrome.runtime.lastError.message);
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
  for (const mutation of mutations) {
    for (const node of mutation.addedNodes) {
      if (node.nodeName === "SCRIPT" && !node.src) {
        const text = node.textContent || "";
        if (REDIRECT_PATTERN.test(text) && PAYMENT_DOMAIN_REGEX.test(text)) {
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
          observer.disconnect();
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
