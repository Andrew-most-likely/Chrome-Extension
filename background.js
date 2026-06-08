// ============================================================
// CONFIGURATION
// Proxy URL lives in config.js (gitignored). Copy config.example.js
// to config.js and fill in your Vercel deployment URL.
// The actual API key is stored in Vercel environment variables.
// ============================================================

importScripts("config.js");

const PROXY_URL = CONFIG.PROXY_URL;

// ============================================================
// HELPERS
// ============================================================

function shouldSkip(url) {
  if (!url) return true;
  if (url.startsWith("chrome://")) return true;
  if (url.startsWith("chrome-extension://")) return true;
  if (url.startsWith("about:")) return true;
  if (url.startsWith("edge://")) return true;
  if (url.startsWith("data:")) return true;
  if (url.startsWith("file://")) return true;
  return false;
}

function buildWarningUrl(originalUrl, threatType, source, detail) {
  const base = chrome.runtime.getURL("warning.html");
  const params = new URLSearchParams({
    url: originalUrl,
    threat: threatType || "UNKNOWN_THREAT",
    source: source || "safebrowsing",
  });
  if (detail) params.set("detail", detail);
  return `${base}?${params.toString()}`;
}

// ============================================================
// SAFE BROWSING API
// ============================================================

async function checkSafeBrowsing(url) {
  if (!PROXY_URL || PROXY_URL.includes("your-project")) return null;

  try {
    const response = await fetch(PROXY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      console.warn("[PhishingDetector] Proxy error:", response.status);
      return null;
    }

    const data = await response.json();
    if (data.matches && data.matches.length > 0) {
      return data.matches[0].threatType;
    }
    return null;
  } catch (err) {
    console.error("[PhishingDetector] Proxy fetch failed:", err);
    return null;
  }
}

// ============================================================
// BYPASS LIST (session — cleared when browser closes)
// ============================================================

async function isBypassed(url) {
  return new Promise((resolve) => {
    chrome.storage.session.get({ bypassed: [] }, (data) => {
      resolve(data.bypassed.includes(url));
    });
  });
}

async function addBypass(url) {
  return new Promise((resolve) => {
    chrome.storage.session.get({ bypassed: [] }, (data) => {
      const list = data.bypassed;
      if (!list.includes(url)) list.push(url);
      chrome.storage.session.set({ bypassed: list }, resolve);
    });
  });
}

// ============================================================
// STATS
// ============================================================

async function incrementBlockedCount() {
  return new Promise((resolve) => {
    chrome.storage.session.get({ blockedCount: 0 }, (data) => {
      chrome.storage.session.set({ blockedCount: data.blockedCount + 1 }, resolve);
    });
  });
}

// ============================================================
// CORE INTERCEPT LOGIC
// ============================================================

async function handleNavigation(tabId, url) {
  if (shouldSkip(url)) return;
  if (await isBypassed(url)) {
    console.log("[PhishingDetector] Bypassed (user allowed):", url);
    return;
  }

  const threatType = await checkSafeBrowsing(url);
  if (threatType) {
    console.warn("[PhishingDetector] THREAT DETECTED:", threatType, url);
    await incrementBlockedCount();
    const warningUrl = buildWarningUrl(url, threatType, "safebrowsing");
    chrome.tabs.update(tabId, { url: warningUrl });
  }
}

// ============================================================
// NAVIGATION LISTENER
// onCommitted fires when the navigation is committed to the tab,
// giving us a valid tabId and url to redirect away from.
// ============================================================

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return; // top-level frame only
  handleNavigation(details.tabId, details.url);
});

// ============================================================
// MESSAGE LISTENER
// Handles messages from content.js, warning.js, and popup.js
// ============================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Content script detected a payment redirect in inline scripts
  if (message.type === "PAYMENT_REDIRECT_DETECTED") {
    const { url, detail } = message;
    const tabId = sender.tab?.id;

    if (!tabId) {
      sendResponse({ status: "error", reason: "no tab id" });
      return false;
    }

    isBypassed(url).then((bypassed) => {
      if (bypassed) {
        sendResponse({ status: "bypassed" });
        return;
      }
      incrementBlockedCount();
      const warningUrl = buildWarningUrl(url, "PAYMENT_REDIRECT", "contentscript", detail);
      chrome.tabs.update(tabId, { url: warningUrl });
      sendResponse({ status: "redirected" });
    });

    return true; // keep channel open for async response
  }

  // Warning page: user clicked "Proceed anyway"
  if (message.type === "ADD_BYPASS") {
    addBypass(message.url).then(() => {
      sendResponse({ status: "ok" });
    });
    return true;
  }

  // Popup: request session stats
  if (message.type === "GET_STATS") {
    chrome.storage.session.get({ blockedCount: 0, bypassed: [] }, (data) => {
      sendResponse({ blockedCount: data.blockedCount, bypassed: data.bypassed });
    });
    return true;
  }
});
