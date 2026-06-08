// ============================================================
// CONFIGURATION
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
// PERSISTENT BLOCK HISTORY (survives browser restarts)
// ============================================================

async function logBlockedSite(url, threatType) {
  let domain = url;
  try { domain = new URL(url).hostname; } catch (_) {}

  const entry = {
    url,
    domain,
    type: threatType,
    timestamp: Date.now(),
  };

  return new Promise((resolve) => {
    chrome.storage.local.get({ history: [], tally: {} }, (data) => {
      // Keep most recent 200 entries
      const history = [entry, ...data.history].slice(0, 200);
      const tally = { ...data.tally };
      tally[threatType] = (tally[threatType] || 0) + 1;
      tally.total = (tally.total || 0) + 1;
      chrome.storage.local.set({ history, tally }, resolve);
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
    await logBlockedSite(url, threatType);
    const warningUrl = buildWarningUrl(url, threatType, "safebrowsing");
    chrome.tabs.update(tabId, { url: warningUrl });
  }
}

// ============================================================
// NAVIGATION LISTENER
// ============================================================

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  handleNavigation(details.tabId, details.url);
});

// ============================================================
// MESSAGE LISTENER
// ============================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Content script detected a payment redirect
  if (message.type === "PAYMENT_REDIRECT_DETECTED") {
    const { sourceUrl, redirectUrl, detail } = message;
    const tabId = sender.tab?.id;

    if (!tabId) {
      sendResponse({ status: "error", reason: "no tab id" });
      return false;
    }

    isBypassed(sourceUrl).then(async (bypassed) => {
      if (bypassed) {
        sendResponse({ status: "bypassed" });
        return;
      }
      await logBlockedSite(redirectUrl, "PAYMENT_REDIRECT");
      const warningUrl = buildWarningUrl(redirectUrl, "PAYMENT_REDIRECT", "contentscript", detail);
      chrome.tabs.update(tabId, { url: warningUrl });
      sendResponse({ status: "redirected" });
    });

    return true;
  }

  // Warning page: user clicked "Go back to safety"
  // history.back() would return to the malicious URL and re-trigger the warning,
  // so background navigates the tab to the new tab page instead.
  if (message.type === "GO_BACK_SAFE") {
    chrome.tabs.update(sender.tab.id, { url: "chrome://newtab" });
    sendResponse({ status: "ok" });
    return false;
  }

  // Warning page: user clicked "Proceed anyway"
  if (message.type === "ADD_BYPASS") {
    addBypass(message.url).then(() => {
      sendResponse({ status: "ok" });
    });
    return true;
  }

  // Popup: request stats
  if (message.type === "GET_STATS") {
    chrome.storage.local.get({ history: [], tally: {} }, (localData) => {
      chrome.storage.session.get({ bypassed: [] }, (sessionData) => {
        sendResponse({
          tally: localData.tally,
          history: localData.history.slice(0, 20), // send most recent 20
          bypassed: sessionData.bypassed,
        });
      });
    });
    return true;
  }
});
