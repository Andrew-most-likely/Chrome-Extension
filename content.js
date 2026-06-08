// ============================================================
// PAYMENT REDIRECT DETECTOR — Content Script
// Scans inline <script> tags for redirect patterns that point
// to known payment services (common phishing technique).
// ============================================================

const PAYMENT_DOMAINS = [
  "paypal.com",
  "stripe.com",
  "venmo.com",
  "cash.app",
  "cashapp.com",
  "coinbase.com",
  "zelle.com",
  "blockchain.com",
  "kraken.com",
  "binance.com",
  "wise.com",
  "transferwise.com",
  "squarecash.com",
  "apple.com/pay",
  "pay.google.com",
  "moneygram.com",
  "westernunion.com",
];

const REDIRECT_PATTERNS = [
  /window\.location\s*=/,
  /location\.href\s*=/,
  /location\.replace\s*\(/,
  /location\.assign\s*\(/,
  /window\.location\.href\s*=/,
  /window\.location\.replace\s*\(/,
  /window\.location\.assign\s*\(/,
];

const PAYMENT_DOMAIN_REGEX = new RegExp(
  PAYMENT_DOMAINS.map((d) => d.replace(".", "\\.")).join("|"),
  "i"
);

function containsPaymentRedirect(scriptText) {
  const hasRedirect = REDIRECT_PATTERNS.some((p) => p.test(scriptText));
  if (!hasRedirect) return false;
  return PAYMENT_DOMAIN_REGEX.test(scriptText);
}

function extractSnippet(scriptText) {
  for (const pattern of REDIRECT_PATTERNS) {
    const match = pattern.exec(scriptText);
    if (match) {
      const start = Math.max(0, match.index - 20);
      const end = Math.min(scriptText.length, match.index + 100);
      return scriptText.slice(start, end).replace(/\s+/g, " ").trim();
    }
  }
  return "";
}

function reportAndStop(snippet) {
  chrome.runtime.sendMessage(
    {
      type: "PAYMENT_REDIRECT_DETECTED",
      url: window.location.href,
      detail: snippet,
    },
    (response) => {
      if (chrome.runtime.lastError) {
        console.warn("[PhishingDetector]", chrome.runtime.lastError.message);
      }
    }
  );
}

function scanInlineScript(scriptEl) {
  const text = scriptEl.textContent;
  if (!text) return false;
  if (containsPaymentRedirect(text)) {
    reportAndStop(extractSnippet(text));
    return true;
  }
  return false;
}

// ---- Initial scan of all existing inline scripts ----
function scanAll() {
  const scripts = document.querySelectorAll("script:not([src])");
  for (const script of scripts) {
    if (scanInlineScript(script)) return; // stop after first hit
  }
}

scanAll();

// ---- Watch for dynamically injected inline scripts ----
const observer = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    for (const node of mutation.addedNodes) {
      if (node.nodeName === "SCRIPT" && !node.src) {
        if (scanInlineScript(node)) {
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
